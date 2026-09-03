#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sys_domain.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "TPHVPNLifecycle.h"

struct options {
    const char *xray;
    const char *config;
    const char *candidate;
    const char *rollback;
    const char *stop;
    const char *reload;
    const char *ready;
    const char *result;
    const char *interface_name;
    char bypass_interface[IFNAMSIZ];
    char bypass_gateway[INET_ADDRSTRLEN];
    const char *workdir;
    const char *asset_dir;
    uid_t uid;
    gid_t gid;
    pid_t app_pid;
    int mtu;
};

static volatile sig_atomic_t interrupted = 0;

static void handle_signal(int signal_number) {
    (void)signal_number;
    interrupted = 1;
}

static void usage(void) {
    fprintf(stderr,
            "usage: TPHVPNHelper --xray PATH --config PATH --candidate PATH "
            "--rollback PATH --stop PATH --reload PATH --ready PATH --result PATH --interface utunN "
            "--bypass-interface enN --app-pid PID --uid UID "
            "--gid GID --mtu MTU --workdir PATH --asset-dir PATH|-\n");
}

static bool parse_unsigned(const char *value, unsigned long *result) {
    if (value == NULL || *value == '\0') return false;
    errno = 0;
    char *end = NULL;
    unsigned long parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') return false;
    *result = parsed;
    return true;
}

static bool valid_bypass_interface_name(const char *value) {
    if (value == NULL || *value == '\0' || strlen(value) >= IFNAMSIZ) return false;
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; ++cursor) {
        if ((*cursor >= 'a' && *cursor <= 'z')
            || (*cursor >= 'A' && *cursor <= 'Z')
            || (*cursor >= '0' && *cursor <= '9')
            || *cursor == '_' || *cursor == '-') continue;
        return false;
    }
    return strncmp(value, "utun", 4) != 0
        && strncmp(value, "tun", 3) != 0
        && strncmp(value, "tap", 3) != 0;
}

static bool parse_options(int argc, char **argv, struct options *out) {
    memset(out, 0, sizeof(*out));
    out->asset_dir = "-";

    for (int index = 1; index < argc; index += 2) {
        if (index + 1 >= argc) return false;
        const char *key = argv[index];
        const char *value = argv[index + 1];
        unsigned long number = 0;

        if (strcmp(key, "--xray") == 0) out->xray = value;
        else if (strcmp(key, "--config") == 0) out->config = value;
        else if (strcmp(key, "--candidate") == 0) out->candidate = value;
        else if (strcmp(key, "--rollback") == 0) out->rollback = value;
        else if (strcmp(key, "--stop") == 0) out->stop = value;
        else if (strcmp(key, "--reload") == 0) out->reload = value;
        else if (strcmp(key, "--ready") == 0) out->ready = value;
        else if (strcmp(key, "--result") == 0) out->result = value;
        else if (strcmp(key, "--interface") == 0) out->interface_name = value;
        else if (strcmp(key, "--bypass-interface") == 0) {
            if (!valid_bypass_interface_name(value)
                || strlcpy(out->bypass_interface, value, sizeof(out->bypass_interface))
                    >= sizeof(out->bypass_interface)) return false;
        }
        else if (strcmp(key, "--workdir") == 0) out->workdir = value;
        else if (strcmp(key, "--asset-dir") == 0) out->asset_dir = value;
        else if (strcmp(key, "--uid") == 0 && parse_unsigned(value, &number)) out->uid = (uid_t)number;
        else if (strcmp(key, "--gid") == 0 && parse_unsigned(value, &number)) out->gid = (gid_t)number;
        else if (strcmp(key, "--app-pid") == 0 && parse_unsigned(value, &number)) out->app_pid = (pid_t)number;
        else if (strcmp(key, "--mtu") == 0 && parse_unsigned(value, &number)) out->mtu = (int)number;
        else return false;
    }

    return out->xray && out->config && out->candidate && out->rollback
        && out->stop && out->reload && out->ready && out->result
        && out->interface_name && out->bypass_interface[0] != '\0'
        && out->workdir && out->uid > 0 && out->gid > 0
        && out->app_pid > 1 && out->mtu >= 1280 && out->mtu <= 9000;
}

static bool absolute_path(const char *path) {
    return path != NULL && path[0] == '/';
}

static bool expected_child_path(const char *workdir, const char *path, const char *name) {
    char expected[PATH_MAX];
    return snprintf(expected, sizeof(expected), "%s/%s", workdir, name) < (int)sizeof(expected)
        && strcmp(path, expected) == 0;
}

/// Закрепляем настоящий пользовательский каталог одним descriptor'ом. Это не
/// даёт заменить его symlink'ом между проверкой и root-записью ready-файла.
static int open_workdir(const struct options *options) {
    char resolved[PATH_MAX];
    if (realpath(options->workdir, resolved) == NULL || strcmp(resolved, options->workdir) != 0) {
        fprintf(stderr, "VPN workdir must not contain symlinks\n");
        return -1;
    }
    int descriptor = open(options->workdir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (descriptor < 0) {
        perror("open(VPN workdir)");
        return -1;
    }
    struct stat status;
    if (fstat(descriptor, &status) != 0 || !S_ISDIR(status.st_mode) || status.st_uid != options->uid) {
        fprintf(stderr, "VPN workdir has unsafe ownership\n");
        close(descriptor);
        return -1;
    }
    if (!expected_child_path(options->workdir, options->config, "xray-system-vpn.json")
        || !expected_child_path(options->workdir, options->candidate, "xray-system-vpn.candidate.json")
        || !expected_child_path(options->workdir, options->rollback, "xray-system-vpn.rollback.json")
        || !expected_child_path(options->workdir, options->stop, "system-vpn.stop")
        || !expected_child_path(options->workdir, options->reload, "system-vpn.reload")
        || !expected_child_path(options->workdir, options->ready, "system-vpn.ready")
        || !expected_child_path(options->workdir, options->result, "system-vpn.result")) {
        fprintf(stderr, "VPN service files must stay inside the workdir\n");
        close(descriptor);
        return -1;
    }
    return descriptor;
}

static int interface_index(const char *name) {
    if (name == NULL || strncmp(name, "utun", 4) != 0) return -1;
    unsigned long parsed = 0;
    if (!parse_unsigned(name + 4, &parsed) || parsed > 1023) return -1;
    return (int)parsed;
}

static int open_utun(const char *name) {
    int index = interface_index(name);
    if (index < 0) {
        fprintf(stderr, "invalid utun interface name: %s\n", name ? name : "(null)");
        return -1;
    }

    int descriptor = socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (descriptor < 0) {
        perror("socket(AF_SYSTEM)");
        return -1;
    }

    struct ctl_info info;
    memset(&info, 0, sizeof(info));
    strlcpy(info.ctl_name, "com.apple.net.utun_control", sizeof(info.ctl_name));
    if (ioctl(descriptor, CTLIOCGINFO, &info) != 0) {
        perror("CTLIOCGINFO");
        close(descriptor);
        return -1;
    }

    struct sockaddr_ctl address;
    memset(&address, 0, sizeof(address));
    address.sc_len = sizeof(address);
    address.sc_family = AF_SYSTEM;
    address.ss_sysaddr = AF_SYS_CONTROL;
    address.sc_id = info.ctl_id;
    address.sc_unit = (uint32_t)index + 1;

    if (connect(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0) {
        perror("connect(utun)");
        close(descriptor);
        return -1;
    }
    return descriptor;
}

static int run_command(const char *path, char *const arguments[], bool quiet) {
    pid_t child = fork();
    if (child < 0) {
        perror("fork(command)");
        return -1;
    }
    if (child == 0) {
        if (quiet) {
            int null_fd = open("/dev/null", O_WRONLY);
            if (null_fd >= 0) {
                dup2(null_fd, STDOUT_FILENO);
                dup2(null_fd, STDERR_FILENO);
                close(null_fd);
            }
        }
        execv(path, arguments);
        _exit(127);
    }

    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno == EINTR) continue;
        return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/// Получает gateway физического интерфейса непосредственно перед установкой
/// /1-маршрутов. Делать это в Swift до диалога администратора нельзя: за время
/// подтверждения Mac может переключиться между Wi-Fi и хотспотом.
static bool resolve_bypass_gateway(
    const char *bypass_interface,
    char bypass_gateway[INET_ADDRSTRLEN]
) {
    int descriptors[2];
    if (pipe(descriptors) != 0) {
        perror("pipe(route get)");
        return false;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork(route get)");
        close(descriptors[0]);
        close(descriptors[1]);
        return false;
    }
    if (child == 0) {
        close(descriptors[0]);
        dup2(descriptors[1], STDOUT_FILENO);
        int null_fd = open("/dev/null", O_WRONLY);
        if (null_fd >= 0) {
            dup2(null_fd, STDERR_FILENO);
            close(null_fd);
        }
        close(descriptors[1]);
        char *arguments[] = {
            "/sbin/route", "-n", "get", "-ifscope",
            (char *)bypass_interface, "default", NULL
        };
        execv(arguments[0], arguments);
        _exit(127);
    }

    close(descriptors[1]);
    char output[4096];
    size_t used = 0;
    while (used + 1 < sizeof(output)) {
        ssize_t count = read(descriptors[0], output + used, sizeof(output) - used - 1);
        if (count > 0) {
            used += (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        break;
    }
    close(descriptors[0]);
    output[used] = '\0';

    int status = 0;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "failed to resolve gateway for %s\n", bypass_interface);
        return false;
    }

    const char *cursor = output;
    while ((cursor = strstr(cursor, "gateway:")) != NULL) {
        cursor += strlen("gateway:");
        while (*cursor == ' ' || *cursor == '\t') cursor++;
        size_t length = strcspn(cursor, " \t\r\n");
        if (length > 0 && length < INET_ADDRSTRLEN) {
            memcpy(bypass_gateway, cursor, length);
            bypass_gateway[length] = '\0';
            struct in_addr address;
            if (inet_pton(AF_INET, bypass_gateway, &address) == 1) return true;
        }
    }
    fprintf(stderr, "no IPv4 gateway for %s\n", bypass_interface);
    return false;
}

static bool configure_interface(const struct options *options) {
    char mtu[16];
    snprintf(mtu, sizeof(mtu), "%d", options->mtu);

    char *ipv4[] = {
        "/sbin/ifconfig", (char *)options->interface_name, "inet",
        "169.254.10.2", "169.254.10.1", "netmask", "255.255.255.252",
        "mtu", mtu, "up", NULL
    };
    if (run_command(ipv4[0], ipv4, false) != 0) {
        fprintf(stderr, "failed to configure IPv4 on %s\n", options->interface_name);
        return false;
    }

    // Link-local IPv6 makes IPv6 routes through the point-to-point interface
    // routable. macOS may already auto-create one; an alias failure is harmless.
    char *ipv6[] = {
        "/sbin/ifconfig", (char *)options->interface_name, "inet6",
        "fe80::a9fe:a02", "prefixlen", "64", "alias", NULL
    };
    (void)run_command(ipv6[0], ipv6, true);
    return true;
}

struct route_state {
    bool bypass_ipv4;
    bool ipv4_low;
    bool ipv4_high;
    bool ipv6_low;
    bool ipv6_high;
    char bypass_interface[IFNAMSIZ];
    char bypass_gateway[INET_ADDRSTRLEN];
};

static int scoped_default_action(
    const char *action, const char *gateway, const char *interface_name, bool quiet
) {
    char *arguments[] = {
        "/sbin/route", "-n", (char *)action, "-net",
        "-ifscope", (char *)interface_name, "default", (char *)gateway, NULL
    };
    return run_command(arguments[0], arguments, quiet);
}

static int scoped_default_command(
    bool add, const char *gateway, const char *interface_name, bool quiet
) {
    return scoped_default_action(add ? "add" : "delete", gateway, interface_name, quiet);
}

static int route_command(bool add, bool ipv6, const char *network, const char *interface_name, bool quiet) {
    char *ipv4_arguments[] = {
        "/sbin/route", "-n", add ? "add" : "delete", "-net",
        (char *)network, "-iface", (char *)interface_name, NULL
    };
    char *ipv6_arguments[] = {
        "/sbin/route", "-n", add ? "add" : "delete", "-inet6", "-net",
        (char *)network, "-iface", (char *)interface_name, NULL
    };
    return run_command("/sbin/route", ipv6 ? ipv6_arguments : ipv4_arguments, quiet);
}

static void remove_routes(const struct options *options, struct route_state *routes) {
    if (routes->ipv6_high) route_command(false, true, "8000::/1", options->interface_name, true);
    if (routes->ipv6_low) route_command(false, true, "::/1", options->interface_name, true);
    if (routes->ipv4_high) route_command(false, false, "128.0.0.0/1", options->interface_name, true);
    if (routes->ipv4_low) route_command(false, false, "0.0.0.0/1", options->interface_name, true);
    if (routes->bypass_ipv4) {
        scoped_default_command(
            false, routes->bypass_gateway, routes->bypass_interface, true
        );
    }
    memset(routes, 0, sizeof(*routes));
}

static bool add_routes(const struct options *options, struct route_state *routes) {
    // IP_BOUND_IF ограничивает сокет интерфейсом, но без scoped route macOS
    // всё равно выбирает более специфичные /1 через utun и возвращает
    // ENETUNREACH. Этот default видят только сокеты, привязанные к en0.
    if (scoped_default_command(
            true, options->bypass_gateway, options->bypass_interface, false
        ) != 0) return false;
    routes->bypass_ipv4 = true;
    strlcpy(routes->bypass_interface, options->bypass_interface, sizeof(routes->bypass_interface));
    strlcpy(routes->bypass_gateway, options->bypass_gateway, sizeof(routes->bypass_gateway));
    if (route_command(true, false, "0.0.0.0/1", options->interface_name, false) != 0) return false;
    routes->ipv4_low = true;
    if (route_command(true, false, "128.0.0.0/1", options->interface_name, false) != 0) return false;
    routes->ipv4_high = true;
    if (route_command(true, true, "::/1", options->interface_name, false) != 0) return false;
    routes->ipv6_low = true;
    if (route_command(true, true, "8000::/1", options->interface_name, false) != 0) return false;
    routes->ipv6_high = true;
    return true;
}

struct bypass_transition {
    bool prepared;
    bool same_interface;
    char interface_name[IFNAMSIZ];
    char gateway[INET_ADDRSTRLEN];
};

/// Подготавливает новый scoped default, не трогая /1-маршруты через utun.
/// Поэтому при любой ошибке соединение остаётся fail-closed, а не уходит Direct.
static bool prepare_bypass_transition(
    struct route_state *routes,
    const char *interface_name,
    struct bypass_transition *transition
) {
    memset(transition, 0, sizeof(*transition));
    if (!routes->bypass_ipv4 || !valid_bypass_interface_name(interface_name)) return false;
    if (if_nametoindex(interface_name) == 0) return false;

    if (!resolve_bypass_gateway(interface_name, transition->gateway)) return false;
    strlcpy(transition->interface_name, interface_name, sizeof(transition->interface_name));
    transition->same_interface = strcmp(interface_name, routes->bypass_interface) == 0;

    if (transition->same_interface) {
        if (strcmp(transition->gateway, routes->bypass_gateway) == 0) {
            transition->prepared = true;
            return true;
        }
        if (scoped_default_action(
                "change", transition->gateway, interface_name, false
            ) != 0) {
            // Старый gateway уже может быть недоступен. Удаление scoped route
            // не раскрывает системный трафик: /1 kill-switch остаётся на utun.
            if (scoped_default_command(
                    false, routes->bypass_gateway, routes->bypass_interface, true
                ) != 0) return false;
            if (scoped_default_command(
                    true, transition->gateway, interface_name, false
                ) != 0) {
                (void)scoped_default_command(
                    true, routes->bypass_gateway, routes->bypass_interface, true
                );
                return false;
            }
        }
    } else if (scoped_default_command(
                   true, transition->gateway, interface_name, false
               ) != 0) {
        return false;
    }
    transition->prepared = true;
    return true;
}

static void commit_bypass_transition(
    struct route_state *routes,
    const struct bypass_transition *transition
) {
    if (!transition->prepared) return;
    if (!transition->same_interface) {
        (void)scoped_default_command(
            false, routes->bypass_gateway, routes->bypass_interface, true
        );
    }
    strlcpy(routes->bypass_interface, transition->interface_name, sizeof(routes->bypass_interface));
    strlcpy(routes->bypass_gateway, transition->gateway, sizeof(routes->bypass_gateway));
}

static void rollback_bypass_transition(
    const struct route_state *routes,
    const struct bypass_transition *transition
) {
    if (!transition->prepared) return;
    if (transition->same_interface) {
        if (strcmp(transition->gateway, routes->bypass_gateway) != 0) {
            (void)scoped_default_action(
                "change", routes->bypass_gateway, routes->bypass_interface, true
            );
        }
    } else {
        (void)scoped_default_command(
            false, transition->gateway, transition->interface_name, true
        );
    }
}

static pid_t start_xray(
    const struct options *options,
    const char *config_path,
    int tun_descriptor,
    int workdir_descriptor
) {
    pid_t child = fork();
    if (child < 0) {
        perror("fork(xray)");
        return -1;
    }
    if (child != 0) return child;

    char descriptor[16];
    snprintf(descriptor, sizeof(descriptor), "%d", tun_descriptor);
    if (fcntl(tun_descriptor, F_SETFD, 0) != 0
        || setenv("XRAY_TUN_FD", descriptor, 1) != 0) {
        _exit(125);
    }
    if (strcmp(options->asset_dir, "-") != 0) {
        if (setenv("XRAY_LOCATION_ASSET", options->asset_dir, 1) != 0) _exit(125);
    }
    if (fchdir(workdir_descriptor) != 0) _exit(125);

    // Подписка управляет конфигом xray, поэтому сбрасываем все root-права до
    // чтения и исполнения этого конфига.
    if (setgroups(0, NULL) != 0 || setgid(options->gid) != 0 || setuid(options->uid) != 0) {
        _exit(126);
    }

    char *arguments[] = {
        (char *)options->xray, "run", "-config", (char *)config_path, NULL
    };
    execv(options->xray, arguments);
    _exit(127);
}

static bool child_alive(pid_t child) {
    if (child <= 0) return false;
    if (kill(child, 0) == 0) return true;
    return errno == EPERM;
}

static bool wait_until_started(pid_t child);

static int stop_child(pid_t child) {
    if (child <= 0) return 0;
    kill(child, SIGTERM);
    for (int attempt = 0; attempt < 30; ++attempt) {
        int status = 0;
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) return status;
        if (result < 0 && errno != EINTR) return 0;
        usleep(100000);
    }
    kill(child, SIGKILL);
    int status = 0;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    return status;
}

static bool write_ready(const struct options *options, int workdir_descriptor, pid_t child) {
    int descriptor = openat(
        workdir_descriptor, "system-vpn.ready",
        O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644
    );
    if (descriptor < 0) {
        perror("open(ready)");
        return false;
    }
    dprintf(descriptor, "%d\n", child);
    fchown(descriptor, options->uid, options->gid);
    close(descriptor);
    return true;
}

static bool valid_owned_regular_at(
    int workdir_descriptor, const char *name, uid_t owner
) {
    int descriptor = openat(workdir_descriptor, name, O_RDONLY | O_NOFOLLOW);
    if (descriptor < 0) return false;
    struct stat status;
    bool valid = fstat(descriptor, &status) == 0
        && S_ISREG(status.st_mode)
        && status.st_uid == owner;
    close(descriptor);
    return valid;
}

static bool copy_regular_at(
    int workdir_descriptor,
    const char *source_name,
    const char *destination_name,
    uid_t owner,
    gid_t group
) {
    int input = openat(workdir_descriptor, source_name, O_RDONLY | O_NOFOLLOW);
    if (input < 0) return false;
    struct stat input_status;
    if (fstat(input, &input_status) != 0
        || !S_ISREG(input_status.st_mode)
        || input_status.st_uid != owner) {
        close(input);
        return false;
    }

    const char *temporary_name = "xray-system-vpn.rollback.tmp";
    unlinkat(workdir_descriptor, temporary_name, 0);
    int output = openat(
        workdir_descriptor,
        temporary_name,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
        0600
    );
    if (output < 0) {
        close(input);
        return false;
    }

    bool ok = true;
    char buffer[16384];
    for (;;) {
        ssize_t count = read(input, buffer, sizeof(buffer));
        if (count > 0) {
            size_t written = 0;
            while (written < (size_t)count) {
                ssize_t part = write(output, buffer + written, (size_t)count - written);
                if (part > 0) {
                    written += (size_t)part;
                    continue;
                }
                if (part < 0 && errno == EINTR) continue;
                ok = false;
                break;
            }
            if (!ok) break;
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) ok = false;
        break;
    }
    if (fchown(output, owner, group) != 0 || fsync(output) != 0) ok = false;
    close(input);
    close(output);

    if (!ok || renameat(
            workdir_descriptor, temporary_name,
            workdir_descriptor, destination_name
        ) != 0) {
        unlinkat(workdir_descriptor, temporary_name, 0);
        return false;
    }
    (void)fsync(workdir_descriptor);
    return true;
}

static bool promote_candidate(int workdir_descriptor, uid_t owner) {
    if (!valid_owned_regular_at(
            workdir_descriptor, "xray-system-vpn.candidate.json", owner
        )) return false;
    if (renameat(
            workdir_descriptor, "xray-system-vpn.candidate.json",
            workdir_descriptor, "xray-system-vpn.json"
        ) != 0) return false;
    (void)fsync(workdir_descriptor);
    return true;
}

static bool write_reload_result(
    const struct options *options,
    int workdir_descriptor,
    const char *generation,
    tph_reload_outcome outcome,
    pid_t child
) {
    const char *outcome_name = "fatal";
    if (outcome == TPH_RELOAD_ACCEPTED) outcome_name = "accepted";
    else if (outcome == TPH_RELOAD_RECOVERED) outcome_name = "recovered";
    else if (outcome == TPH_RELOAD_REJECTED) outcome_name = "rejected";

    const char *temporary_name = "system-vpn.result.tmp";
    unlinkat(workdir_descriptor, temporary_name, 0);
    int descriptor = openat(
        workdir_descriptor,
        temporary_name,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
        0644
    );
    if (descriptor < 0) return false;
    bool ok = dprintf(descriptor, "%s %s %d\n", generation, outcome_name, child) > 0;
    if (fchown(descriptor, options->uid, options->gid) != 0 || fsync(descriptor) != 0) ok = false;
    close(descriptor);
    if (!ok || renameat(
            workdir_descriptor, temporary_name,
            workdir_descriptor, "system-vpn.result"
        ) != 0) {
        unlinkat(workdir_descriptor, temporary_name, 0);
        return false;
    }
    (void)fsync(workdir_descriptor);
    return true;
}

struct reload_request {
    char generation[65];
    bool network_rebind;
    bool route_only;
    char bypass_interface[IFNAMSIZ];
};

static bool valid_generation(const char *generation) {
    size_t count = strlen(generation);
    if (count == 0 || count > 64) return false;
    for (size_t index = 0; index < count; ++index) {
        char value = generation[index];
        if (!((value >= 'a' && value <= 'z')
              || (value >= 'A' && value <= 'Z')
              || (value >= '0' && value <= '9')
              || value == '-')) return false;
    }
    return true;
}

static bool read_reload_request(
    int workdir_descriptor,
    struct reload_request *request
) {
    memset(request, 0, sizeof(*request));
    int descriptor = openat(
        workdir_descriptor, "system-vpn.reload", O_RDONLY | O_NOFOLLOW
    );
    if (descriptor < 0) return false;
    char buffer[128];
    ssize_t count = read(descriptor, buffer, sizeof(buffer) - 1);
    close(descriptor);
    if (count <= 0) return false;
    buffer[count] = '\0';

    char *save = NULL;
    char *generation = strtok_r(buffer, " \t\r\n", &save);
    char *interface_name = strtok_r(NULL, " \t\r\n", &save);
    char *mode = strtok_r(NULL, " \t\r\n", &save);
    if (strtok_r(NULL, " \t\r\n", &save) != NULL
        || generation == NULL || !valid_generation(generation)) return false;
    strlcpy(request->generation, generation, sizeof(request->generation));

    if (interface_name != NULL) {
        if (!valid_bypass_interface_name(interface_name)) return false;
        if (strlcpy(
                request->bypass_interface,
                interface_name,
                sizeof(request->bypass_interface)
            ) >= sizeof(request->bypass_interface)) return false;
        request->network_rebind = true;
    }
    if (mode != NULL) {
        if (!request->network_rebind || strcmp(mode, "route") != 0) return false;
        request->route_only = true;
    }
    return true;
}

struct reload_context {
    const struct options *options;
    int tun_descriptor;
    int workdir_descriptor;
    const char *generation;
};

static bool reload_snapshot_active(void *opaque) {
    struct reload_context *context = opaque;
    if (!valid_owned_regular_at(
            context->workdir_descriptor,
            "xray-system-vpn.candidate.json",
            context->options->uid
        )) return false;
    return copy_regular_at(
        context->workdir_descriptor,
        "xray-system-vpn.json",
        "xray-system-vpn.rollback.json",
        context->options->uid,
        context->options->gid
    );
}

static void reload_stop_child(void *opaque, pid_t child) {
    (void)opaque;
    (void)stop_child(child);
}

static pid_t reload_start_candidate(void *opaque) {
    struct reload_context *context = opaque;
    return start_xray(
        context->options,
        context->options->candidate,
        context->tun_descriptor,
        context->workdir_descriptor
    );
}

static pid_t reload_start_active(void *opaque) {
    struct reload_context *context = opaque;
    return start_xray(
        context->options,
        context->options->config,
        context->tun_descriptor,
        context->workdir_descriptor
    );
}

static bool reload_wait_started(void *opaque, pid_t child) {
    (void)opaque;
    return wait_until_started(child);
}

static bool reload_promote_candidate(void *opaque) {
    struct reload_context *context = opaque;
    return promote_candidate(context->workdir_descriptor, context->options->uid);
}

static bool reload_restore_active(void *opaque) {
    struct reload_context *context = opaque;
    return copy_regular_at(
        context->workdir_descriptor,
        "xray-system-vpn.rollback.json",
        "xray-system-vpn.json",
        context->options->uid,
        context->options->gid
    );
}

static bool reload_publish_result(
    void *opaque, tph_reload_outcome outcome, pid_t child
) {
    struct reload_context *context = opaque;
    bool ready = true;
    if (child > 0 && (outcome == TPH_RELOAD_ACCEPTED || outcome == TPH_RELOAD_RECOVERED)) {
        ready = write_ready(context->options, context->workdir_descriptor, child);
    }
    bool result = write_reload_result(
        context->options,
        context->workdir_descriptor,
        context->generation,
        outcome,
        child > 0 ? child : 0
    );
    return ready && result;
}

static bool wait_until_started(pid_t child) {
    for (int attempt = 0; attempt < 8; ++attempt) {
        usleep(50000);
        int status = 0;
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) return false;
        if (result < 0 && errno != EINTR) return false;
    }
    return child_alive(child);
}

int main(int argc, char **argv) {
    // LaunchDaemon передаёт launcher один общий socket. Перенаправляем туда
    // и stderr, чтобы ни одна причина падения не потерялась.
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) return 74;

    struct options options;
    if (!parse_options(argc, argv, &options)) {
        usage();
        return 64;
    }
    if (geteuid() != 0) {
        fprintf(stderr, "TPHVPNHelper must be authorized by macOS\n");
        return 77;
    }
    if (!absolute_path(options.xray) || !absolute_path(options.config)
        || !absolute_path(options.candidate) || !absolute_path(options.rollback)
        || !absolute_path(options.stop) || !absolute_path(options.reload)
        || !absolute_path(options.ready) || !absolute_path(options.result)
        || !absolute_path(options.workdir)
        || (strcmp(options.asset_dir, "-") != 0 && !absolute_path(options.asset_dir))) {
        fprintf(stderr, "all helper paths must be absolute\n");
        return 64;
    }
    if (access(options.xray, X_OK) != 0 || access(options.config, R_OK) != 0) {
        perror("xray/config access");
        return 66;
    }
    int workdir_descriptor = open_workdir(&options);
    if (workdir_descriptor < 0) return 73;
    if (faccessat(workdir_descriptor, "system-vpn.stop", F_OK, 0) == 0) {
        close(workdir_descriptor);
        return 0;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGHUP, handle_signal);
    signal(SIGPIPE, SIG_IGN);
    unlinkat(workdir_descriptor, "system-vpn.ready", 0);
    unlinkat(workdir_descriptor, "system-vpn.reload", 0);
    unlinkat(workdir_descriptor, "system-vpn.result", 0);
    unlinkat(workdir_descriptor, "xray-system-vpn.candidate.json", 0);
    unlinkat(workdir_descriptor, "xray-system-vpn.rollback.json", 0);

    int tun_descriptor = open_utun(options.interface_name);
    if (tun_descriptor < 0) {
        close(workdir_descriptor);
        return 69;
    }
    if (!configure_interface(&options)) {
        close(tun_descriptor);
        close(workdir_descriptor);
        return 69;
    }

    pid_t xray = start_xray(&options, options.config, tun_descriptor, workdir_descriptor);
    if (xray < 0 || !wait_until_started(xray)) {
        if (xray > 0) stop_child(xray);
        close(tun_descriptor);
        close(workdir_descriptor);
        fprintf(stderr, "xray exited before VPN routes were installed\n");
        return 70;
    }

    // Разрешаем gateway в самый последний момент: Wi-Fi/хотспот может
    // переключиться даже во время короткого запуска Xray.
    if (!resolve_bypass_gateway(options.bypass_interface, options.bypass_gateway)) {
        stop_child(xray);
        close(tun_descriptor);
        close(workdir_descriptor);
        return 69;
    }

    struct route_state routes = {0};
    if (!add_routes(&options, &routes)) {
        fprintf(stderr, "failed to install system VPN routes\n");
        remove_routes(&options, &routes);
        stop_child(xray);
        close(tun_descriptor);
        close(workdir_descriptor);
        return 71;
    }
    if (!write_ready(&options, workdir_descriptor, xray)) {
        remove_routes(&options, &routes);
        stop_child(xray);
        close(tun_descriptor);
        close(workdir_descriptor);
        return 73;
    }

    printf("TPH_VPN_READY interface=%s xray_pid=%d uid=%u\n",
           options.interface_name, xray, options.uid);
    fflush(stdout);

    bool requested_stop = false;
    int child_status = 0;
    int crash_recoveries = 0;
    time_t child_started_at = time(NULL);
    while (!interrupted) {
        if (faccessat(workdir_descriptor, "system-vpn.stop", F_OK, 0) == 0
            || (kill(options.app_pid, 0) != 0 && errno == ESRCH)) {
            requested_stop = true;
            break;
        }

        int status = 0;
        pid_t result = waitpid(xray, &status, WNOHANG);
        if (result == xray) {
            child_status = status;
            xray = -1;
            time_t now = time(NULL);
            if (child_started_at > 0 && now - child_started_at >= 30) {
                crash_recoveries = 0;
            }
            while (xray <= 0 && crash_recoveries < 3) {
                crash_recoveries++;
                xray = start_xray(&options, options.config, tun_descriptor, workdir_descriptor);
                if (xray > 0 && wait_until_started(xray)
                    && write_ready(&options, workdir_descriptor, xray)) {
                    break;
                }
                if (xray > 0) stop_child(xray);
                xray = -1;
                fprintf(stderr, "automatic xray recovery failed attempt=%d\n", crash_recoveries);
                usleep(200000);
            }
            if (xray <= 0) {
                fprintf(stderr, "xray exceeded automatic recovery budget\n");
                break;
            }
            child_started_at = time(NULL);
            printf("TPH_VPN_XRAY_RECOVERED xray_pid=%d attempt=%d\n", xray, crash_recoveries);
            fflush(stdout);
            continue;
        }
        if (result < 0 && errno != EINTR) break;

        if (faccessat(workdir_descriptor, "system-vpn.reload", F_OK, 0) == 0) {
            struct reload_request request;
            if (!read_reload_request(workdir_descriptor, &request)) {
                memset(&request, 0, sizeof(request));
                strlcpy(request.generation, "invalid", sizeof(request.generation));
            }
            unlinkat(workdir_descriptor, "system-vpn.reload", 0);

            struct bypass_transition bypass_transition = {0};
            if (request.network_rebind
                && !prepare_bypass_transition(
                    &routes, request.bypass_interface, &bypass_transition
                )) {
                unlinkat(workdir_descriptor, "xray-system-vpn.candidate.json", 0);
                (void)write_reload_result(
                    &options,
                    workdir_descriptor,
                    request.generation,
                    TPH_RELOAD_REJECTED,
                    xray
                );
                fprintf(stderr,
                        "TPH_VPN_NETWORK_REBIND_REJECTED generation=%s interface=%s\n",
                        request.generation,
                        request.bypass_interface[0] != '\0' ? request.bypass_interface : "invalid");
                usleep(200000);
                continue;
            }

            // При смене IP/gateway на том же interface Xray уже привязан к
            // правильному устройству. Меняем только scoped route: PID, utun,
            // WireGuard-сессии и fallback state остаются живы.
            if (request.route_only) {
                bool same_interface = strcmp(
                    request.bypass_interface, routes.bypass_interface
                ) == 0;
                bool snapshotted = same_interface && copy_regular_at(
                    workdir_descriptor,
                    "xray-system-vpn.json",
                    "xray-system-vpn.rollback.json",
                    options.uid,
                    options.gid
                );
                bool promoted = snapshotted
                    && promote_candidate(workdir_descriptor, options.uid);
                if (promoted) {
                    commit_bypass_transition(&routes, &bypass_transition);
                    (void)write_ready(&options, workdir_descriptor, xray);
                    (void)write_reload_result(
                        &options,
                        workdir_descriptor,
                        request.generation,
                        TPH_RELOAD_ACCEPTED,
                        xray
                    );
                    printf("TPH_VPN_ROUTE_REBOUND generation=%s interface=%s xray_pid=%d\n",
                           request.generation, request.bypass_interface, xray);
                } else {
                    rollback_bypass_transition(&routes, &bypass_transition);
                    if (snapshotted) {
                        (void)copy_regular_at(
                            workdir_descriptor,
                            "xray-system-vpn.rollback.json",
                            "xray-system-vpn.json",
                            options.uid,
                            options.gid
                        );
                    }
                    unlinkat(workdir_descriptor, "xray-system-vpn.candidate.json", 0);
                    (void)write_reload_result(
                        &options,
                        workdir_descriptor,
                        request.generation,
                        TPH_RELOAD_REJECTED,
                        xray
                    );
                    fprintf(stderr,
                            "TPH_VPN_ROUTE_REBIND_REJECTED generation=%s interface=%s\n",
                            request.generation, request.bypass_interface);
                }
                unlinkat(workdir_descriptor, "xray-system-vpn.rollback.json", 0);
                fflush(stdout);
                usleep(200000);
                continue;
            }

            struct reload_context context = {
                .options = &options,
                .tun_descriptor = tun_descriptor,
                .workdir_descriptor = workdir_descriptor,
                .generation = request.generation,
            };
            tph_reload_operations operations = {
                .context = &context,
                .snapshot_active = reload_snapshot_active,
                .stop_child = reload_stop_child,
                .start_candidate = reload_start_candidate,
                .start_active = reload_start_active,
                .wait_started = reload_wait_started,
                .promote_candidate = reload_promote_candidate,
                .restore_active = reload_restore_active,
                // Commit/rollback physical route before exposing completion
                // to Swift. /1 kill-switch routes stay installed throughout.
                .publish_result = request.network_rebind ? NULL : reload_publish_result,
            };
            tph_reload_result reload_result = tph_perform_reload(xray, &operations);
            if (request.network_rebind) {
                if (reload_result.outcome == TPH_RELOAD_ACCEPTED) {
                    commit_bypass_transition(&routes, &bypass_transition);
                } else {
                    rollback_bypass_transition(&routes, &bypass_transition);
                }
                (void)reload_publish_result(
                    &context, reload_result.outcome, reload_result.child
                );
            }
            if (reload_result.outcome != TPH_RELOAD_ACCEPTED) {
                unlinkat(workdir_descriptor, "xray-system-vpn.candidate.json", 0);
            }
            xray = reload_result.child;
            if (reload_result.outcome == TPH_RELOAD_FATAL || xray <= 0) {
                xray = -1;
                child_status = 70 << 8;
                fprintf(stderr, "TPH_VPN_RELOAD_FATAL generation=%s\n", request.generation);
                break;
            }
            crash_recoveries = 0;
            child_started_at = time(NULL);
            if (reload_result.outcome == TPH_RELOAD_ACCEPTED) {
                printf("TPH_VPN_RELOAD_ACCEPTED generation=%s xray_pid=%d\n", request.generation, xray);
            } else if (reload_result.outcome == TPH_RELOAD_RECOVERED) {
                printf("TPH_VPN_RELOAD_RECOVERED generation=%s xray_pid=%d\n", request.generation, xray);
            } else {
                printf("TPH_VPN_RELOAD_REJECTED generation=%s xray_pid=%d\n", request.generation, xray);
            }
            fflush(stdout);
        }
        usleep(200000);
    }

    // Сначала возвращаем системные маршруты, чтобы даже медленно завершающийся
    // xray не оставил Mac без сети.
    unlinkat(workdir_descriptor, "system-vpn.ready", 0);
    remove_routes(&options, &routes);
    if (xray > 0) child_status = stop_child(xray);
    close(tun_descriptor);
    unlinkat(workdir_descriptor, "system-vpn.reload", 0);
    unlinkat(workdir_descriptor, "xray-system-vpn.candidate.json", 0);
    unlinkat(workdir_descriptor, "xray-system-vpn.rollback.json", 0);
    unlinkat(workdir_descriptor, "system-vpn.stop", 0);
    close(workdir_descriptor);

    if (requested_stop || interrupted) return 0;
    if (WIFEXITED(child_status)) return WEXITSTATUS(child_status);
    if (WIFSIGNALED(child_status)) return 128 + WTERMSIG(child_status);
    return 70;
}
