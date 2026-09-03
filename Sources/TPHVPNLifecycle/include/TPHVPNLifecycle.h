#ifndef TPH_VPN_LIFECYCLE_H
#define TPH_VPN_LIFECYCLE_H

#include <stdbool.h>
#include <sys/types.h>

typedef enum {
    TPH_RELOAD_ACCEPTED,
    TPH_RELOAD_RECOVERED,
    TPH_RELOAD_REJECTED,
    TPH_RELOAD_FATAL,
} tph_reload_outcome;

typedef struct {
    void *context;
    bool (*snapshot_active)(void *context);
    void (*stop_child)(void *context, pid_t child);
    pid_t (*start_candidate)(void *context);
    pid_t (*start_active)(void *context);
    bool (*wait_started)(void *context, pid_t child);
    bool (*promote_candidate)(void *context);
    bool (*restore_active)(void *context);
    bool (*publish_result)(void *context, tph_reload_outcome outcome, pid_t child);
} tph_reload_operations;

typedef struct {
    tph_reload_outcome outcome;
    pid_t child;
} tph_reload_result;

tph_reload_result tph_perform_reload(pid_t current, const tph_reload_operations *operations);

#endif
