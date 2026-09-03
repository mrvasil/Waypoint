#include "TPHVPNLifecycle.h"

#include <stdio.h>
#include <string.h>

struct fake_context {
    char calls[64];
    size_t used;
    bool snapshot_ok;
    bool candidate_ok;
    bool active_ok;
    bool promote_ok;
};

static void record(struct fake_context *context, char value) {
    context->calls[context->used++] = value;
    context->calls[context->used] = '\0';
}

static bool snapshot_active(void *opaque) {
    struct fake_context *context = opaque;
    record(context, 'S');
    return context->snapshot_ok;
}

static void stop_child(void *opaque, pid_t child) {
    (void)child;
    record(opaque, 'T');
}

static pid_t start_candidate(void *opaque) {
    record(opaque, 'C');
    return 100;
}

static pid_t start_active(void *opaque) {
    record(opaque, 'A');
    return 200;
}

static bool wait_started(void *opaque, pid_t child) {
    struct fake_context *context = opaque;
    record(context, 'W');
    return child == 100 ? context->candidate_ok : context->active_ok;
}

static bool promote_candidate(void *opaque) {
    struct fake_context *context = opaque;
    record(context, 'P');
    return context->promote_ok;
}

static bool restore_active(void *opaque) {
    record(opaque, 'O');
    return true;
}

static bool publish_result(void *opaque, tph_reload_outcome outcome, pid_t child) {
    (void)outcome;
    (void)child;
    record(opaque, 'R');
    return true;
}

static tph_reload_operations operations_for(struct fake_context *context) {
    tph_reload_operations operations = {
        .context = context,
        .snapshot_active = snapshot_active,
        .stop_child = stop_child,
        .start_candidate = start_candidate,
        .start_active = start_active,
        .wait_started = wait_started,
        .promote_candidate = promote_candidate,
        .restore_active = restore_active,
        .publish_result = publish_result,
    };
    return operations;
}

static int test_recovers_after_candidate_failure(void) {
    struct fake_context context = {
        .snapshot_ok = true, .candidate_ok = false, .active_ok = true, .promote_ok = true,
    };
    tph_reload_operations operations = operations_for(&context);
    tph_reload_result result = tph_perform_reload(42, &operations);
    if (result.outcome != TPH_RELOAD_RECOVERED || result.child != 200) {
        fprintf(stderr, "expected recovered child 200, got outcome=%d child=%d\n", result.outcome, result.child);
        return 1;
    }
    if (strcmp(context.calls, "STCWTOAWR") != 0) {
        fprintf(stderr, "unexpected callback order: %s\n", context.calls);
        return 1;
    }
    puts("helper lifecycle: recovered active config after candidate failure");
    return 0;
}

static int test_accepts_started_candidate(void) {
    struct fake_context context = {
        .snapshot_ok = true, .candidate_ok = true, .active_ok = true, .promote_ok = true,
    };
    tph_reload_operations operations = operations_for(&context);
    tph_reload_result result = tph_perform_reload(42, &operations);
    if (result.outcome != TPH_RELOAD_ACCEPTED || result.child != 100) {
        fprintf(stderr, "expected accepted child 100, got outcome=%d child=%d\n", result.outcome, result.child);
        return 1;
    }
    if (strcmp(context.calls, "STCWPR") != 0) {
        fprintf(stderr, "unexpected accepted callback order: %s\n", context.calls);
        return 1;
    }
    puts("helper lifecycle: accepted started candidate");
    return 0;
}

int main(void) {
    if (test_recovers_after_candidate_failure() != 0) return 1;
    if (test_accepts_started_candidate() != 0) return 1;
    return 0;
}
