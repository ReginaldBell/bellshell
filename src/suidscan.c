#define _XOPEN_SOURCE 700
#define _GNU_SOURCE

#include <errno.h>
#include <ftw.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../include/security.h"
#include "../include/suidscan.h"
#include "../include/utils.h"

/* Global scan context */
static suidscan_context_t g_scan_ctx = {0};

/* External access to shutdown flag */
extern volatile sig_atomic_t *get_shutdown_flag(void);

/* FTW callback for SUID/SGID scanning */
static int suidscan_cb(const char *fpath, const struct stat *sb,
                       int typeflag, struct FTW *ftwbuf) {
    (void)ftwbuf;
    
    volatile sig_atomic_t *shutdown_flag = get_shutdown_flag();
    if (*shutdown_flag) {
        return 1;
    }

    if (typeflag != FTW_F && typeflag != FTW_SL) {
        return 0;
    }

    /* Security: Re-stat to prevent TOCTOU attacks */
    struct stat current_stat;
    if (lstat(fpath, &current_stat) == -1) {
        return 0;
    }

    if (current_stat.st_ino != sb->st_ino ||
        current_stat.st_dev != sb->st_dev) {
        char msg[512];
        snprintf(msg, sizeof(msg),
                 "File replaced during scan: %s", fpath);
        audit_log_secure(LOG_WARNING, "SECURITY", msg);
        return 0;
    }

    bool is_suid = (current_stat.st_mode & S_ISUID) != 0;
    bool is_sgid = (current_stat.st_mode & S_ISGID) != 0;

    if (is_suid || (is_sgid && g_scan_ctx.include_sgid)) {
        char type_str[16] = {0};
        if (is_suid && is_sgid) {
            snprintf(type_str, sizeof(type_str), "SUID+SGID");
        } else if (is_suid) {
            snprintf(type_str, sizeof(type_str), "SUID");
        } else {
            snprintf(type_str, sizeof(type_str), "SGID");
        }

        if (g_scan_ctx.verbose) {
            printf("[%s] %s\n", type_str, fpath);
            printf("       Owner: uid=%d gid=%d Mode: %04o\n",
                   current_stat.st_uid, current_stat.st_gid,
                   current_stat.st_mode & 07777);
        } else {
            printf("[%s] %s (uid=%d)\n", type_str, fpath,
                   current_stat.st_uid);
        }

        if (is_suid) g_scan_ctx.count_suid++;
        if (is_sgid) g_scan_ctx.count_sgid++;

        char audit_msg[512];
        snprintf(audit_msg, sizeof(audit_msg),
                 "Found %s binary: %s (uid=%d)",
                 type_str, fpath, current_stat.st_uid);
        audit_log_secure(LOG_INFO, "SECURITY", audit_msg);
    }

    g_scan_ctx.files_scanned++;
    if (g_scan_ctx.files_scanned % 1000 == 0) {
        time_t elapsed = time(NULL) - g_scan_ctx.start_time;
        fprintf(stderr, "\r[Scanning... %d files checked, %lds elapsed]",
                g_scan_ctx.files_scanned, (long)elapsed);
        fflush(stderr);
    }

    return 0;
}

/* Parse SUID scan options */
static int parse_suidscan_options(int argc, char **argv,
                                  const char **start_dir,
                                  bool *include_sgid,
                                  bool *verbose) {
    *start_dir = NULL;
    *include_sgid = false;
    *verbose = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "suidscan: -d requires a directory argument\n");
                return -1;
            }
            *start_dir = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0) {
            *include_sgid = true;
        } else if (strcmp(argv[i], "-v") == 0) {
            *verbose = true;
        } else if (strcmp(argv[i], "-h") == 0 ||
                   strcmp(argv[i], "--help") == 0) {
            printf("Usage: suidscan [options]\n");
            printf("Options:\n");
            printf("  -d <dir>  Start directory (default: /usr /bin /sbin)\n");
            printf("  -s        Include SGID binaries\n");
            printf("  -v        Verbose output\n");
            printf("  -h        Show this help\n");
            return -1;
        } else {
            fprintf(stderr, "suidscan: unknown option: %s\n", argv[i]);
            return -1;
        }
    }

    return 0;
}

/* Implementation of SUID scan */
int builtin_suidscan_impl(int argc, char **argv) {
    const char *start_dir = NULL;
    bool include_sgid = false;
    bool verbose = false;

    if (parse_suidscan_options(argc, argv, &start_dir,
                               &include_sgid, &verbose) != 0) {
        return CMD_ERROR;
    }

    const char *default_paths[] = {
        "/usr/bin", "/usr/sbin", "/bin", "/sbin", NULL
    };
    const char **search_paths;

    if (start_dir) {
        if (!is_safe_scan_path(start_dir)) {
            fprintf(stderr,
                    "suidscan: refusing to scan dangerous path: %s\n",
                    start_dir);
            audit_log_secure(LOG_WARNING, "SECURITY",
                      "Attempted scan of dangerous path blocked");
            return CMD_ERROR;
        }

        static const char *custom_paths[2];
        custom_paths[0] = start_dir;
        custom_paths[1] = NULL;
        search_paths = custom_paths;
    } else {
        search_paths = default_paths;
    }

    memset(&g_scan_ctx, 0, sizeof(g_scan_ctx));
    g_scan_ctx.include_sgid = include_sgid;
    g_scan_ctx.verbose = verbose;
    g_scan_ctx.start_time = time(NULL);

    char audit_msg[256];
    snprintf(audit_msg, sizeof(audit_msg),
             "SUID scan initiated by uid=%d", getuid());
    audit_log_secure(LOG_NOTICE, "SECURITY", audit_msg);

    printf("\n=== SUID/SGID Binary Scanner ===\n");
    printf("Scanning paths: ");
    for (int i = 0; search_paths[i] != NULL; i++) {
        printf("%s ", search_paths[i]);
    }
    printf("\n");
    if (include_sgid) {
        printf("Mode: SUID + SGID binaries\n");
    } else {
        printf("Mode: SUID binaries only\n");
    }
    printf("This may take some time...\n\n");

    int flags = FTW_PHYS | FTW_MOUNT;
    int max_fd = 15;

    for (int i = 0; search_paths[i] != NULL; i++) {
        volatile sig_atomic_t *shutdown_flag = get_shutdown_flag();
        if (*shutdown_flag) {
            printf("\n[Scan interrupted by user]\n");
            break;
        }

        if (nftw(search_paths[i], suidscan_cb, max_fd, flags) == -1) {
            if (errno == EACCES) {
                fprintf(stderr,
                        "\nWarning: Permission denied for %s (continuing)\n",
                        search_paths[i]);
            } else {
                fprintf(stderr,
                        "\nsuidscan: nftw(%s): %s\n",
                        search_paths[i], strerror(errno));
            }
        }
    }

    fprintf(stderr, "\r%*s\r", 60, "");

    printf("\n=== Scan Complete ===\n");
    printf("Files scanned: %d\n", g_scan_ctx.files_scanned);
    printf("SUID binaries found: %d\n", g_scan_ctx.count_suid);
    if (include_sgid) {
        printf("SGID binaries found: %d\n", g_scan_ctx.count_sgid);
    }

    time_t elapsed = time(NULL) - g_scan_ctx.start_time;
    printf("Time elapsed: %ld seconds\n", (long)elapsed);

    snprintf(audit_msg, sizeof(audit_msg),
             "SUID scan completed: %d SUID, %d SGID binaries found",
             g_scan_ctx.count_suid, g_scan_ctx.count_sgid);
    audit_log_secure(LOG_INFO, "INFO", audit_msg);

    return CMD_SUCCESS;
}
