#include "WaypointVPNLifecycle.h"

static waypoint_reload_result finish(
    const waypoint_reload_operations *operations,
    waypoint_reload_outcome outcome,
    pid_t child
) {
    if (operations->publish_result != NULL) {
        (void)operations->publish_result(operations->context, outcome, child);
    }
    return (waypoint_reload_result){.outcome = outcome, .child = child};
}

waypoint_reload_result waypoint_perform_reload(pid_t current, const waypoint_reload_operations *operations) {
    if (operations == NULL
        || operations->snapshot_active == NULL
        || operations->stop_child == NULL
        || operations->start_candidate == NULL
        || operations->start_active == NULL
        || operations->wait_started == NULL
        || operations->promote_candidate == NULL
        || operations->restore_active == NULL) {
        return (waypoint_reload_result){.outcome = WAYPOINT_RELOAD_FATAL, .child = current};
    }

    if (!operations->snapshot_active(operations->context)) {
        return finish(operations, WAYPOINT_RELOAD_REJECTED, current);
    }

    operations->stop_child(operations->context, current);
    pid_t candidate = operations->start_candidate(operations->context);
    if (candidate > 0 && operations->wait_started(operations->context, candidate)) {
        if (operations->promote_candidate(operations->context)) {
            return finish(operations, WAYPOINT_RELOAD_ACCEPTED, candidate);
        }
        operations->stop_child(operations->context, candidate);
    } else if (candidate > 0) {
        operations->stop_child(operations->context, candidate);
    }

    if (!operations->restore_active(operations->context)) {
        return finish(operations, WAYPOINT_RELOAD_FATAL, -1);
    }
    pid_t recovered = operations->start_active(operations->context);
    if (recovered > 0 && operations->wait_started(operations->context, recovered)) {
        return finish(operations, WAYPOINT_RELOAD_RECOVERED, recovered);
    }
    if (recovered > 0) operations->stop_child(operations->context, recovered);
    return finish(operations, WAYPOINT_RELOAD_FATAL, -1);
}
