#ifndef WAYPOINT_VPN_LIFECYCLE_H
#define WAYPOINT_VPN_LIFECYCLE_H

#include <stdbool.h>
#include <sys/types.h>

typedef enum {
    WAYPOINT_RELOAD_ACCEPTED,
    WAYPOINT_RELOAD_RECOVERED,
    WAYPOINT_RELOAD_REJECTED,
    WAYPOINT_RELOAD_FATAL,
} waypoint_reload_outcome;

typedef struct {
    void *context;
    bool (*snapshot_active)(void *context);
    void (*stop_child)(void *context, pid_t child);
    pid_t (*start_candidate)(void *context);
    pid_t (*start_active)(void *context);
    bool (*wait_started)(void *context, pid_t child);
    bool (*promote_candidate)(void *context);
    bool (*restore_active)(void *context);
    bool (*publish_result)(void *context, waypoint_reload_outcome outcome, pid_t child);
} waypoint_reload_operations;

typedef struct {
    waypoint_reload_outcome outcome;
    pid_t child;
} waypoint_reload_result;

waypoint_reload_result waypoint_perform_reload(pid_t current, const waypoint_reload_operations *operations);

#endif
