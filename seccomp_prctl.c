#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

#define log_error(...)                                              \
do {                                                                \
    fprintf(stdout, "[ERROR]%s: %d: ", __FILE__, __LINE__);         \
    if (errno)                                                      \
        fprintf(stdout, "[errno %d: %s] ", errno, strerror(errno)); \
    fprintf(stdout, __VA_ARGS__);                                   \
    fprintf(stdout, "\n");                                          \
} while (0)

#define log_debug(...)                                              \
do {                                                                \
    fprintf(stdout, "[DEBUG]%s: %d: ", __FILE__, __LINE__);         \
    fprintf(stdout, __VA_ARGS__);                                   \
    fprintf(stdout, "\n");                                          \
} while (0)


int filter_syscalls() {
    int ret = -1;

    log_debug("filtering syscalls with bpf...");

    struct sock_filter code[] = {
        /* op,   jt,   jf,     k    */
        {0x20, 0x00, 0x00, 0x00000004},
        {0x15, 0x00, 0x05, 0xc000003e},
        {0x20, 0x00, 0x00, 0x00000000},
        {0x35, 0x00, 0x01, 0x40000000},
        {0x15, 0x00, 0x02, 0xffffffff},
        {0x15, 0x01, 0x00, 0x0000010c}, // 268 fchmodat
        {0x06, 0x00, 0x00, 0x7fff0000},
        {0x06, 0x00, 0x00, 0x00000000},
    };

    struct sock_fprog bpf = {
        .len = ARRAY_SIZE(code),
        .filter = code,
    };

    ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (ret < 0) { log_error("error prctl set no new privs"); return EXIT_FAILURE; }

    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &bpf);
    if (ret < 0) { log_error("error prctl set seccomp filter"); return EXIT_FAILURE; }

    return 0;
}

extern char **environ;

int main(int argc, char *argv[]) {
    int ret = -1;

    ret = filter_syscalls();
    if (ret != 0) { log_error("filter syscall failed"); return EXIT_FAILURE; }

    char *prog = "/bin/bash";
    ret = execve(prog, (char *[]){prog, 0}, environ);
    log_debug("%d", ret);
    if (ret < 0) { log_error("exec failed"); return EXIT_FAILURE; }

    return EXIT_SUCCESS;
}
