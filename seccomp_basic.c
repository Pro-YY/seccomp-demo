#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <seccomp.h>

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
    scmp_filter_ctx ctx;

    log_debug("filtering syscalls...");
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) { log_error("error seccomp ctx init"); return ret; }

    // prohibits specified syscall
    ret = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(fchmodat), 0);
    if (ret < 0) { log_error("error seccomp rule add: fchmodat"); goto out; }

    ret = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(symlinkat), 0);
    if (ret < 0) { log_error("error seccomp rule add: symlinkat"); goto out; }

    // limit syscall arguments
    ret = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(write), 1,
            SCMP_A2_64(SCMP_CMP_GT, 2048));
    if (ret < 0) { log_error("error seccomp rule add: write"); goto out; }

    ret = seccomp_load(ctx);
    if (ret < 0) { log_error("error seccomp load"); goto out; }

out:
    seccomp_release(ctx);
    if (ret != 0) return -1;

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
