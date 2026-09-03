#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <net/if.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define TPH_PROTOCOL_MAGIC 0x54504856u
#define TPH_PROTOCOL_VERSION 3u
#define TPH_MAX_ARGUMENTS 64u
#define TPH_MAX_ARGUMENT_LENGTH 8192u
#define TPH_MAX_LOG_BYTES (2u * 1024u * 1024u)

#define TPH_DAEMON_LABEL "ru.mrvasil.tunnel-proxy-hub.vpn-daemon"
#define TPH_DAEMON_PATH "/Library/PrivilegedHelperTools/ru.mrvasil.tunnel-proxy-hub.vpn-daemon"
#define TPH_HELPER_PATH "/Library/PrivilegedHelperTools/ru.mrvasil.tunnel-proxy-hub.vpn-helper"
#define TPH_PLIST_PATH "/Library/LaunchDaemons/ru.mrvasil.tunnel-proxy-hub.vpn-daemon.plist"
#define TPH_SOCKET_PATH "/var/run/ru.mrvasil.tunnel-proxy-hub.vpn.sock"

enum response_status {
    response_ok = 0,
    response_version_mismatch = 1,
    response_unauthorized = 2,
    response_malformed = 3,
    response_internal_error = 4,
};

enum client_result {
    client_success = 0,
    client_unavailable,
    client_version_mismatch,
    client_rejected,
    client_failed,
};

struct protocol_header {
    uint32_t magic;
    uint32_t version;
    uint32_t argument_count;
};

struct protocol_response {
    uint32_t magic;
    uint32_t version;
    uint32_t status;
};

struct options {
    const char *helper;
    const char *log;
    const char *ready;
    char **helper_arguments;
    size_t helper_argument_count;
};

struct install_options {
    const char *launcher_source;
    const char *helper_source;
    uid_t allowed_uid;
    gid_t allowed_gid;
};

static volatile sig_atomic_t daemon_interrupted = 0;

static void usage(void) {
    fprintf(stderr,
            "usage: TPHVPNLauncher --helper PATH --log PATH --ready PATH -- [helper arguments]\n");
}

static bool absolute_path(const char *path) {
    return path != NULL && path[0] == '/';
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

static bool parse_options(int argc, char **argv, struct options *out) {
    memset(out, 0, sizeof(*out));
    int index = 1;
    while (index < argc) {
        if (strcmp(argv[index], "--") == 0) {
            out->helper_arguments = &argv[index + 1];
            out->helper_argument_count = (size_t)(argc - index - 1);
            break;
        }
        if (index + 1 >= argc) return false;
        if (strcmp(argv[index], "--helper") == 0) out->helper = argv[index + 1];
        else if (strcmp(argv[index], "--log") == 0) out->log = argv[index + 1];
        else if (strcmp(argv[index], "--ready") == 0) out->ready = argv[index + 1];
        else return false;
        index += 2;
    }
    return absolute_path(out->helper) && absolute_path(out->log)
        && absolute_path(out->ready) && out->helper_arguments != NULL
        && out->helper_argument_count > 0
        && out->helper_argument_count <= TPH_MAX_ARGUMENTS;
}

static bool parse_install_options(int argc, char **argv, struct install_options *out) {
    memset(out, 0, sizeof(*out));
    for (int index = 2; index < argc; index += 2) {
        if (index + 1 >= argc) return false;
        unsigned long number = 0;
        if (strcmp(argv[index], "--launcher-source") == 0) {
            out->launcher_source = argv[index + 1];
        } else if (strcmp(argv[index], "--helper-source") == 0) {
            out->helper_source = argv[index + 1];
        } else if (strcmp(argv[index], "--allowed-uid") == 0
                   && parse_unsigned(argv[index + 1], &number)) {
            out->allowed_uid = (uid_t)number;
        } else if (strcmp(argv[index], "--allowed-gid") == 0
                   && parse_unsigned(argv[index + 1], &number)) {
            out->allowed_gid = (gid_t)number;
        } else {
            return false;
        }
    }
    return absolute_path(out->launcher_source) && absolute_path(out->helper_source)
        && out->allowed_uid > 0 && out->allowed_gid > 0;
}

static ssize_t read_full(int descriptor, void *buffer, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = read(descriptor, (char *)buffer + offset, length - offset);
        if (count > 0) {
            offset += (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        return count == 0 ? 0 : -1;
    }
    return (ssize_t)offset;
}

static bool write_full(int descriptor, const void *buffer, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = write(descriptor, (const char *)buffer + offset, length - offset);
        if (count > 0) {
            offset += (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

static int run_command(const char *path, char *const arguments[], bool quiet) {
    pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        if (quiet) {
            int null_descriptor = open("/dev/null", O_WRONLY);
            if (null_descriptor >= 0) {
                dup2(null_descriptor, STDOUT_FILENO);
                dup2(null_descriptor, STDERR_FILENO);
                close(null_descriptor);
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

static bool copy_regular_file(const char *source, const char *destination, mode_t mode) {
    int input = open(source, O_RDONLY | O_NOFOLLOW);
    if (input < 0) {
        perror("open(source)");
        return false;
    }
    struct stat source_status;
    if (fstat(input, &source_status) != 0 || !S_ISREG(source_status.st_mode)) {
        fprintf(stderr, "installer source is not a regular file: %s\n", source);
        close(input);
        return false;
    }

    char temporary[PATH_MAX];
    if (snprintf(temporary, sizeof(temporary), "%s.new.%d", destination, getpid())
        >= (int)sizeof(temporary)) {
        close(input);
        return false;
    }
    int output = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode);
    if (output < 0) {
        perror("open(destination temporary)");
        close(input);
        return false;
    }

    bool ok = true;
    char buffer[16384];
    for (;;) {
        ssize_t count = read(input, buffer, sizeof(buffer));
        if (count > 0) {
            if (!write_full(output, buffer, (size_t)count)) ok = false;
            if (!ok) break;
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) ok = false;
        break;
    }
    if (fchmod(output, mode) != 0 || fchown(output, 0, 0) != 0 || fsync(output) != 0) ok = false;
    close(input);
    close(output);

    if (!ok || rename(temporary, destination) != 0) {
        if (ok) perror("rename(installed tool)");
        unlink(temporary);
        return false;
    }
    return true;
}

static bool write_daemon_plist(uid_t uid, gid_t gid) {
    char plist[4096];
    int length = snprintf(
        plist, sizeof(plist),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\"><dict>\n"
        "<key>Label</key><string>%s</string>\n"
        "<key>ProgramArguments</key><array>\n"
        "<string>%s</string><string>--daemon</string>\n"
        "<string>--allowed-uid</string><string>%u</string>\n"
        "<string>--allowed-gid</string><string>%u</string>\n"
        "</array>\n"
        "<key>RunAtLoad</key><true/>\n"
        "<key>KeepAlive</key><true/>\n"
        "<key>ThrottleInterval</key><integer>2</integer>\n"
        "<key>Umask</key><integer>63</integer>\n"
        "</dict></plist>\n",
        TPH_DAEMON_LABEL, TPH_DAEMON_PATH, uid, gid
    );
    if (length <= 0 || length >= (int)sizeof(plist)) return false;

    char temporary[PATH_MAX];
    if (snprintf(temporary, sizeof(temporary), "%s.new.%d", TPH_PLIST_PATH, getpid())
        >= (int)sizeof(temporary)) return false;
    int descriptor = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0644);
    if (descriptor < 0) {
        perror("open(daemon plist)");
        return false;
    }
    bool ok = write_full(descriptor, plist, (size_t)length);
    if (fchmod(descriptor, 0644) != 0 || fchown(descriptor, 0, 0) != 0
        || fsync(descriptor) != 0) ok = false;
    close(descriptor);
    if (!ok || rename(temporary, TPH_PLIST_PATH) != 0) {
        if (ok) perror("rename(daemon plist)");
        unlink(temporary);
        return false;
    }
    return true;
}

static int install_main(int argc, char **argv) {
    struct install_options options;
    if (!parse_install_options(argc, argv, &options)) return 64;
    if (geteuid() != 0) {
        fprintf(stderr, "TPH installer must be authorized by macOS\n");
        return 77;
    }
    struct passwd *account = getpwuid(options.allowed_uid);
    if (account == NULL || account->pw_gid != options.allowed_gid) {
        fprintf(stderr, "invalid allowed VPN account\n");
        return 64;
    }
    if (mkdir("/Library/PrivilegedHelperTools", 0755) != 0 && errno != EEXIST) {
        perror("mkdir(PrivilegedHelperTools)");
        return 73;
    }

    char service_target[256];
    snprintf(service_target, sizeof(service_target), "system/%s", TPH_DAEMON_LABEL);
    char *bootout[] = {"/bin/launchctl", "bootout", service_target, NULL};
    (void)run_command(bootout[0], bootout, true);
    for (int attempt = 0; attempt < 20 && access(TPH_SOCKET_PATH, F_OK) == 0; ++attempt) {
        usleep(100000);
    }

    if (!copy_regular_file(options.launcher_source, TPH_DAEMON_PATH, 0755)
        || !copy_regular_file(options.helper_source, TPH_HELPER_PATH, 0755)
        || !write_daemon_plist(options.allowed_uid, options.allowed_gid)) {
        return 73;
    }

    char *bootstrap[] = {"/bin/launchctl", "bootstrap", "system", TPH_PLIST_PATH, NULL};
    if (run_command(bootstrap[0], bootstrap, false) != 0) {
        fprintf(stderr, "failed to register persistent VPN daemon\n");
        return 71;
    }
    char *enable[] = {"/bin/launchctl", "enable", service_target, NULL};
    (void)run_command(enable[0], enable, true);
    char *kickstart[] = {"/bin/launchctl", "kickstart", "-k", service_target, NULL};
    (void)run_command(kickstart[0], kickstart, true);

    printf("TPH_DAEMON_INSTALLED version=%u uid=%u\n", TPH_PROTOCOL_VERSION, options.allowed_uid);
    fflush(stdout);
    return 0;
}

static const char *argument_value(size_t count, char **arguments, const char *key) {
    const char *found = NULL;
    if (count % 2 != 0) return NULL;
    for (size_t index = 0; index < count; index += 2) {
        if (strcmp(arguments[index], key) == 0) {
            if (found != NULL) return NULL;
            found = arguments[index + 1];
        }
    }
    return found;
}

static bool known_helper_key(const char *key) {
    const char *known[] = {
        "--xray", "--config", "--candidate", "--rollback", "--stop", "--reload",
        "--ready", "--result", "--interface",
        "--bypass-interface", "--uid", "--gid", "--app-pid", "--mtu",
        "--workdir", "--asset-dir",
    };
    for (size_t index = 0; index < sizeof(known) / sizeof(known[0]); ++index) {
        if (strcmp(key, known[index]) == 0) return true;
    }
    return false;
}

static bool expected_child_path(const char *workdir, const char *path, const char *name) {
    char expected[PATH_MAX];
    return snprintf(expected, sizeof(expected), "%s/%s", workdir, name) < (int)sizeof(expected)
        && strcmp(path, expected) == 0;
}

static bool validate_helper_request(
    size_t count, char **arguments, uid_t allowed_uid, gid_t allowed_gid
) {
    if (count != 32 || count % 2 != 0) return false;
    for (size_t index = 0; index < count; index += 2) {
        if (!known_helper_key(arguments[index])) return false;
    }

    const char *xray = argument_value(count, arguments, "--xray");
    const char *config = argument_value(count, arguments, "--config");
    const char *candidate = argument_value(count, arguments, "--candidate");
    const char *rollback = argument_value(count, arguments, "--rollback");
    const char *stop = argument_value(count, arguments, "--stop");
    const char *reload = argument_value(count, arguments, "--reload");
    const char *ready = argument_value(count, arguments, "--ready");
    const char *reload_result = argument_value(count, arguments, "--result");
    const char *interface_name = argument_value(count, arguments, "--interface");
    const char *bypass_interface = argument_value(count, arguments, "--bypass-interface");
    const char *uid_text = argument_value(count, arguments, "--uid");
    const char *gid_text = argument_value(count, arguments, "--gid");
    const char *pid_text = argument_value(count, arguments, "--app-pid");
    const char *mtu = argument_value(count, arguments, "--mtu");
    const char *workdir = argument_value(count, arguments, "--workdir");
    const char *asset_dir = argument_value(count, arguments, "--asset-dir");
    if (!xray || !config || !candidate || !rollback || !stop || !reload || !ready
        || !reload_result || !interface_name
        || !bypass_interface || !uid_text || !gid_text || !pid_text || !mtu
        || !workdir || !asset_dir) return false;

    unsigned long uid_number = 0, gid_number = 0, pid_number = 0;
    if (!parse_unsigned(uid_text, &uid_number) || uid_number != allowed_uid
        || !parse_unsigned(gid_text, &gid_number) || gid_number != allowed_gid
        || !parse_unsigned(pid_text, &pid_number) || pid_number <= 1
        || strcmp(mtu, "1500") != 0) return false;

    struct passwd *account = getpwuid(allowed_uid);
    if (account == NULL) return false;
    char expected_workdir[PATH_MAX];
    if (snprintf(expected_workdir, sizeof(expected_workdir),
                 "%s/Library/Application Support/tunnel-proxy-hub", account->pw_dir)
        >= (int)sizeof(expected_workdir) || strcmp(workdir, expected_workdir) != 0) return false;

    char resolved_workdir[PATH_MAX];
    if (realpath(workdir, resolved_workdir) == NULL || strcmp(resolved_workdir, workdir) != 0) return false;
    struct stat workdir_status;
    if (stat(workdir, &workdir_status) != 0 || !S_ISDIR(workdir_status.st_mode)
        || workdir_status.st_uid != allowed_uid) return false;

    if (!expected_child_path(workdir, config, "xray-system-vpn.json")
        || !expected_child_path(workdir, candidate, "xray-system-vpn.candidate.json")
        || !expected_child_path(workdir, rollback, "xray-system-vpn.rollback.json")
        || !expected_child_path(workdir, stop, "system-vpn.stop")
        || !expected_child_path(workdir, reload, "system-vpn.reload")
        || !expected_child_path(workdir, ready, "system-vpn.ready")
        || !expected_child_path(workdir, reload_result, "system-vpn.result")) return false;
    if (!absolute_path(xray) || access(xray, X_OK) != 0) return false;
    if (strcmp(asset_dir, "-") != 0 && !absolute_path(asset_dir)) return false;
    if (strncmp(interface_name, "utun", 4) != 0 || if_nametoindex(bypass_interface) == 0) return false;

    struct proc_bsdinfo process_info;
    int result = proc_pidinfo(
        (pid_t)pid_number, PROC_PIDTBSDINFO, 0, &process_info, sizeof(process_info)
    );
    return result == sizeof(process_info) && process_info.pbi_uid == allowed_uid;
}

static bool secure_installed_helper(void) {
    struct stat status;
    return lstat(TPH_HELPER_PATH, &status) == 0 && S_ISREG(status.st_mode)
        && status.st_uid == 0 && (status.st_mode & 0022) == 0
        && (status.st_mode & S_IXUSR) != 0;
}

static bool send_response(int descriptor, enum response_status status) {
    struct protocol_response response = {
        htonl(TPH_PROTOCOL_MAGIC), htonl(TPH_PROTOCOL_VERSION), htonl((uint32_t)status)
    };
    return write_full(descriptor, &response, sizeof(response));
}

static void free_arguments(size_t count, char **arguments) {
    if (arguments == NULL) return;
    for (size_t index = 0; index < count; ++index) free(arguments[index]);
    free(arguments);
}

static bool receive_arguments(int descriptor, size_t count, char ***out) {
    char **arguments = calloc(count + 1, sizeof(char *));
    if (arguments == NULL) return false;
    for (size_t index = 0; index < count; ++index) {
        uint32_t encoded_length = 0;
        if (read_full(descriptor, &encoded_length, sizeof(encoded_length)) != sizeof(encoded_length)) {
            free_arguments(count, arguments);
            return false;
        }
        uint32_t length = ntohl(encoded_length);
        if (length == 0 || length > TPH_MAX_ARGUMENT_LENGTH) {
            free_arguments(count, arguments);
            return false;
        }
        arguments[index] = calloc((size_t)length + 1, 1);
        if (arguments[index] == NULL
            || read_full(descriptor, arguments[index], length) != (ssize_t)length) {
            free_arguments(count, arguments);
            return false;
        }
    }
    arguments[count] = NULL;
    *out = arguments;
    return true;
}

static void handle_daemon_signal(int signal_number) {
    (void)signal_number;
    daemon_interrupted = 1;
}

static int run_helper_for_client(
    int server_descriptor, int client_descriptor, size_t count, char **arguments
) {
    if (!send_response(client_descriptor, response_ok)) return -1;
    pid_t child = fork();
    if (child < 0) {
        dprintf(client_descriptor, "failed to fork installed VPN helper: %s\n", strerror(errno));
        close(client_descriptor);
        return -1;
    }
    if (child == 0) {
        close(server_descriptor);
        dup2(client_descriptor, STDOUT_FILENO);
        dup2(client_descriptor, STDERR_FILENO);
        if (client_descriptor > STDERR_FILENO) close(client_descriptor);

        char **execution_arguments = calloc(count + 2, sizeof(char *));
        if (execution_arguments == NULL) _exit(125);
        execution_arguments[0] = (char *)TPH_HELPER_PATH;
        for (size_t index = 0; index < count; ++index) execution_arguments[index + 1] = arguments[index];
        execution_arguments[count + 1] = NULL;
        execv(TPH_HELPER_PATH, execution_arguments);
        dprintf(STDERR_FILENO, "failed to execute installed VPN helper: %s\n", strerror(errno));
        _exit(127);
    }

    close(client_descriptor);
    int status = 0;
    for (;;) {
        pid_t result = waitpid(child, &status, 0);
        if (result == child) break;
        if (result < 0 && errno == EINTR) {
            if (daemon_interrupted) kill(child, SIGTERM);
            continue;
        }
        break;
    }
    return status;
}

static void handle_client(
    int server_descriptor, int client_descriptor, uid_t allowed_uid, gid_t allowed_gid
) {
    uid_t peer_uid = 0;
    gid_t peer_gid = 0;
    if (getpeereid(client_descriptor, &peer_uid, &peer_gid) != 0 || peer_uid != allowed_uid) {
        (void)send_response(client_descriptor, response_unauthorized);
        close(client_descriptor);
        return;
    }

    struct protocol_header header;
    if (read_full(client_descriptor, &header, sizeof(header)) != sizeof(header)) {
        close(client_descriptor);
        return;
    }
    uint32_t magic = ntohl(header.magic);
    uint32_t version = ntohl(header.version);
    uint32_t count = ntohl(header.argument_count);
    if (magic != TPH_PROTOCOL_MAGIC || count == 0 || count > TPH_MAX_ARGUMENTS) {
        (void)send_response(client_descriptor, response_malformed);
        close(client_descriptor);
        return;
    }
    if (version != TPH_PROTOCOL_VERSION) {
        (void)send_response(client_descriptor, response_version_mismatch);
        close(client_descriptor);
        return;
    }

    char **arguments = NULL;
    if (!receive_arguments(client_descriptor, count, &arguments)
        || !validate_helper_request(count, arguments, allowed_uid, allowed_gid)) {
        (void)send_response(client_descriptor, response_malformed);
        free_arguments(count, arguments);
        close(client_descriptor);
        return;
    }
    if (!secure_installed_helper()) {
        (void)send_response(client_descriptor, response_internal_error);
        free_arguments(count, arguments);
        close(client_descriptor);
        return;
    }

    (void)run_helper_for_client(server_descriptor, client_descriptor, count, arguments);
    free_arguments(count, arguments);
}

static int daemon_main(int argc, char **argv) {
    if (geteuid() != 0 || argc != 6
        || strcmp(argv[2], "--allowed-uid") != 0
        || strcmp(argv[4], "--allowed-gid") != 0) return 77;
    unsigned long uid_number = 0, gid_number = 0;
    if (!parse_unsigned(argv[3], &uid_number) || uid_number == 0
        || !parse_unsigned(argv[5], &gid_number) || gid_number == 0) return 64;
    uid_t allowed_uid = (uid_t)uid_number;
    gid_t allowed_gid = (gid_t)gid_number;
    struct passwd *account = getpwuid(allowed_uid);
    if (account == NULL || account->pw_gid != allowed_gid) return 64;

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_daemon_signal;
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGHUP, &action, NULL);
    signal(SIGPIPE, SIG_IGN);

    struct stat socket_status;
    if (lstat(TPH_SOCKET_PATH, &socket_status) == 0) {
        if (!S_ISSOCK(socket_status.st_mode) || socket_status.st_uid != 0) return 73;
        if (unlink(TPH_SOCKET_PATH) != 0) return 73;
    } else if (errno != ENOENT) {
        return 73;
    }

    int server = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server < 0) return 69;
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strlcpy(address.sun_path, TPH_SOCKET_PATH, sizeof(address.sun_path));
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) != 0
        || chown(TPH_SOCKET_PATH, allowed_uid, allowed_gid) != 0
        || chmod(TPH_SOCKET_PATH, 0600) != 0
        || listen(server, 4) != 0) {
        close(server);
        unlink(TPH_SOCKET_PATH);
        return 69;
    }

    while (!daemon_interrupted) {
        int client = accept(server, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            break;
        }
        handle_client(server, client, allowed_uid, allowed_gid);
    }
    close(server);
    unlink(TPH_SOCKET_PATH);
    return 0;
}

static int open_log(const char *path) {
    return open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
}

static int stream_output(int input, const struct options *options) {
    int log_descriptor = open_log(options->log);
    if (log_descriptor < 0) {
        perror("VPN log");
        return 73;
    }
    bool ready_seen = access(options->ready, F_OK) == 0;
    size_t log_bytes = 0;
    static const char rotation_marker[] = "--- предыдущий VPN-лог обрезан по лимиту 2 МБ ---\n";
    char buffer[4096];
    for (;;) {
        ssize_t count = read(input, buffer, sizeof(buffer));
        if (count > 0) {
            size_t chunk_size = (size_t)count;
            if (log_bytes + chunk_size > TPH_MAX_LOG_BYTES) {
                if (ftruncate(log_descriptor, 0) != 0
                    || lseek(log_descriptor, 0, SEEK_SET) < 0
                    || !write_full(
                        log_descriptor,
                        rotation_marker,
                        sizeof(rotation_marker) - 1
                    )) {
                    close(log_descriptor);
                    return 74;
                }
                log_bytes = sizeof(rotation_marker) - 1;
            }
            if (!write_full(log_descriptor, buffer, (size_t)count)) {
                close(log_descriptor);
                return 74;
            }
            log_bytes += chunk_size;
            if (access(options->ready, F_OK) == 0) ready_seen = true;
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        break;
    }
    close(log_descriptor);
    return ready_seen ? 0 : 70;
}

static bool send_request(int descriptor, const struct options *options) {
    struct protocol_header header = {
        htonl(TPH_PROTOCOL_MAGIC), htonl(TPH_PROTOCOL_VERSION),
        htonl((uint32_t)options->helper_argument_count),
    };
    if (!write_full(descriptor, &header, sizeof(header))) return false;
    for (size_t index = 0; index < options->helper_argument_count; ++index) {
        size_t length = strlen(options->helper_arguments[index]);
        if (length == 0 || length > TPH_MAX_ARGUMENT_LENGTH) return false;
        uint32_t encoded_length = htonl((uint32_t)length);
        if (!write_full(descriptor, &encoded_length, sizeof(encoded_length))
            || !write_full(descriptor, options->helper_arguments[index], length)) return false;
    }
    return true;
}

static enum client_result run_via_daemon(const struct options *options, int *exit_code) {
    int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0) return client_unavailable;
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strlcpy(address.sun_path, TPH_SOCKET_PATH, sizeof(address.sun_path));
    if (connect(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(descriptor);
        return client_unavailable;
    }
    if (!send_request(descriptor, options)) {
        close(descriptor);
        return client_failed;
    }

    struct protocol_response response;
    if (read_full(descriptor, &response, sizeof(response)) != sizeof(response)
        || ntohl(response.magic) != TPH_PROTOCOL_MAGIC) {
        close(descriptor);
        return client_failed;
    }
    uint32_t status = ntohl(response.status);
    uint32_t version = ntohl(response.version);
    if (status == response_version_mismatch || version != TPH_PROTOCOL_VERSION) {
        close(descriptor);
        return client_version_mismatch;
    }
    if (status != response_ok) {
        fprintf(stderr, "persistent VPN daemon rejected request (status=%u)\n", status);
        close(descriptor);
        return client_rejected;
    }

    *exit_code = stream_output(descriptor, options);
    close(descriptor);
    return client_success;
}

static int authorize_and_execute(
    const char *executable, char *const arguments[], FILE **pipe_out
) {
    AuthorizationRef authorization = NULL;
    OSStatus status = AuthorizationCreate(
        NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &authorization
    );
    if (status != errAuthorizationSuccess) {
        fprintf(stderr, "TPH_AUTH_ERROR status=(%d) stage=create\n", (int)status);
        return 77;
    }

    AuthorizationItem item = {
        kAuthorizationRightExecute, (UInt32)strlen(executable), (void *)executable, 0
    };
    AuthorizationRights rights = {1, &item};
    AuthorizationFlags flags = kAuthorizationFlagInteractionAllowed
        | kAuthorizationFlagPreAuthorize | kAuthorizationFlagExtendRights;
    status = AuthorizationCopyRights(
        authorization, &rights, kAuthorizationEmptyEnvironment, flags, NULL
    );
    if (status == errAuthorizationSuccess) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        status = AuthorizationExecuteWithPrivileges(
            authorization, executable, kAuthorizationFlagDefaults, arguments, pipe_out
        );
#pragma clang diagnostic pop
    }
    AuthorizationFree(authorization, kAuthorizationFlagDestroyRights);
    if (status != errAuthorizationSuccess) {
        fprintf(stderr, "TPH_AUTH_ERROR status=(%d) stage=execute\n", (int)status);
        return 77;
    }
    return 0;
}

static void forward_installer_output(FILE *communications) {
    if (communications == NULL) return;
    char buffer[4096];
    int descriptor = fileno(communications);
    for (;;) {
        ssize_t count = read(descriptor, buffer, sizeof(buffer));
        if (count > 0) {
            (void)write_full(STDERR_FILENO, buffer, (size_t)count);
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        break;
    }
    fclose(communications);
}

static int install_daemon(const struct options *options, const char *self_path) {
    char uid[32], gid[32];
    snprintf(uid, sizeof(uid), "%u", getuid());
    snprintf(gid, sizeof(gid), "%u", getgid());
    char *arguments[] = {
        "--install", "--launcher-source", (char *)self_path,
        "--helper-source", (char *)options->helper,
        "--allowed-uid", uid, "--allowed-gid", gid, NULL,
    };
    FILE *communications = NULL;
    int result = authorize_and_execute(self_path, arguments, &communications);
    if (result != 0) return result;
    forward_installer_output(communications);

    for (int attempt = 0; attempt < 60; ++attempt) {
        if (access(TPH_SOCKET_PATH, R_OK | W_OK) == 0) return 0;
        usleep(100000);
    }
    fprintf(stderr, "persistent VPN daemon did not become ready\n");
    return 70;
}

static bool self_test_log_rotation(void) {
    char directory_template[] = "/tmp/tph-vpn-log-test.XXXXXX";
    char *directory = mkdtemp(directory_template);
    if (directory == NULL) return false;

    char input_path[PATH_MAX], log_path[PATH_MAX], ready_path[PATH_MAX];
    snprintf(input_path, sizeof(input_path), "%s/input", directory);
    snprintf(log_path, sizeof(log_path), "%s/output.log", directory);
    snprintf(ready_path, sizeof(ready_path), "%s/ready", directory);

    bool passed = false;
    int input = open(input_path, O_RDWR | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    int ready = open(ready_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (input < 0 || ready < 0) goto cleanup;
    close(ready);
    ready = -1;

    char chunk[4096];
    memset(chunk, 'L', sizeof(chunk));
    size_t total = 0;
    while (total < TPH_MAX_LOG_BYTES + sizeof(chunk) * 2u) {
        if (!write_full(input, chunk, sizeof(chunk))) goto cleanup;
        total += sizeof(chunk);
    }
    if (lseek(input, 0, SEEK_SET) < 0) goto cleanup;

    struct options options = {.log = log_path, .ready = ready_path};
    if (stream_output(input, &options) != 0) goto cleanup;

    struct stat attributes;
    if (stat(log_path, &attributes) != 0
        || attributes.st_size <= 0
        || (uint64_t)attributes.st_size > TPH_MAX_LOG_BYTES) goto cleanup;
    passed = true;

cleanup:
    if (input >= 0) close(input);
    if (ready >= 0) close(ready);
    unlink(input_path);
    unlink(log_path);
    unlink(ready_path);
    rmdir(directory);
    return passed;
}

static int self_test(void) {
    struct passwd *account = getpwuid(getuid());
    if (account == NULL) return 1;
    char workdir[PATH_MAX], config[PATH_MAX], candidate[PATH_MAX], rollback[PATH_MAX];
    char stop[PATH_MAX], reload[PATH_MAX], ready[PATH_MAX], reload_result[PATH_MAX];
    snprintf(workdir, sizeof(workdir), "%s/Library/Application Support/tunnel-proxy-hub", account->pw_dir);
    snprintf(config, sizeof(config), "%s/xray-system-vpn.json", workdir);
    snprintf(candidate, sizeof(candidate), "%s/xray-system-vpn.candidate.json", workdir);
    snprintf(rollback, sizeof(rollback), "%s/xray-system-vpn.rollback.json", workdir);
    snprintf(stop, sizeof(stop), "%s/system-vpn.stop", workdir);
    snprintf(reload, sizeof(reload), "%s/system-vpn.reload", workdir);
    snprintf(ready, sizeof(ready), "%s/system-vpn.ready", workdir);
    snprintf(reload_result, sizeof(reload_result), "%s/system-vpn.result", workdir);
    char uid[32], gid[32], pid[32];
    snprintf(uid, sizeof(uid), "%u", getuid());
    snprintf(gid, sizeof(gid), "%u", getgid());
    snprintf(pid, sizeof(pid), "%d", getpid());
    char *arguments[] = {
        "--xray", "/usr/bin/true", "--config", config,
        "--candidate", candidate, "--rollback", rollback,
        "--stop", stop, "--reload", reload, "--ready", ready,
        "--result", reload_result, "--interface", "utun99",
        "--bypass-interface", "en0", "--uid", uid, "--gid", gid,
        "--app-pid", pid, "--mtu", "1500", "--workdir", workdir,
        "--asset-dir", "-",
    };
    if (!validate_helper_request(32, arguments, getuid(), getgid())) {
        fprintf(stderr, "self-test: valid request rejected\n");
        return 1;
    }
    arguments[21] = "0";
    if (validate_helper_request(32, arguments, getuid(), getgid())) {
        fprintf(stderr, "self-test: unsafe uid accepted\n");
        return 1;
    }
    if (!self_test_log_rotation()) {
        fprintf(stderr, "self-test: VPN log rotation failed\n");
        return 1;
    }
    printf("TPHVPNLauncher self-test OK (protocol=%u)\n", TPH_PROTOCOL_VERSION);
    return 0;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc > 1 && strcmp(argv[1], "--install") == 0) return install_main(argc, argv);
    if (argc > 1 && strcmp(argv[1], "--daemon") == 0) return daemon_main(argc, argv);
    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) return self_test();

    struct options options;
    if (!parse_options(argc, argv, &options)) {
        usage();
        return 64;
    }
    if (access(options.helper, X_OK) != 0) {
        perror("VPN helper");
        return 66;
    }

    int exit_code = 70;
    enum client_result client = run_via_daemon(&options, &exit_code);
    if (client == client_success) return exit_code;
    if (client == client_rejected || client == client_failed) return 70;

    char self_path[PATH_MAX];
    if (realpath(argv[0], self_path) == NULL || !absolute_path(self_path)) {
        perror("realpath(VPN launcher)");
        return 70;
    }
    int install_result = install_daemon(&options, self_path);
    if (install_result != 0) return install_result;

    client = run_via_daemon(&options, &exit_code);
    if (client == client_success) return exit_code;
    fprintf(stderr, "persistent VPN daemon unavailable after installation\n");
    return 70;
}
