#ifndef SUIDSCAN_H
#define SUIDSCAN_H

#include <stdbool.h>
#include <time.h>

/* SUID/SGID scan context */
typedef struct {
    int count_suid;
    int count_sgid;
    bool include_sgid;
    bool verbose;
    time_t start_time;
    int files_scanned;
} suidscan_context_t;

/* SUID scan implementation */
int builtin_suidscan_impl(int argc, char **argv);

#endif /* SUIDSCAN_H */
