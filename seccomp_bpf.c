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

    ret = seccomp_load(ctx);
    if (ret < 0) { log_error("error seccomp load"); goto out; }


    // export bpf
    int bpf_fd = open("seccomp_filter.bpf", O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (bpf_fd == -1) { log_error("error open"); goto out; }
    ret = seccomp_export_bpf(ctx, bpf_fd);
    if (ret < 0) { log_error("error export"); goto out; }
    close(bpf_fd);
    /*
     hd seccomp_filter.bpf
00000000  20 00 00 00 04 00 00 00  15 00 00 05 3e 00 00 c0  | ...........>...|
00000010  20 00 00 00 00 00 00 00  35 00 00 01 00 00 00 40  | .......5......@|
00000020  15 00 00 02 ff ff ff ff  15 00 01 00 0c 01 00 00  |................|
00000030  06 00 00 00 00 00 ff 7f  06 00 00 00 00 00 00 00  |................|
00000040
     */

    // export pfc
    int pfc_fd = open("seccomp_filter.pfc", O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (pfc_fd == -1) { log_error("error open"); goto out; }
    ret = seccomp_export_pfc(ctx, pfc_fd);
    if (ret < 0) { log_error("error export"); goto out; }
    close(pfc_fd);
    /*
     seccomp_filter.pfc
#
# pseudo filter code start
#
# filter for arch x86_64 (3221225534)
if ($arch == 3221225534)
  # filter for syscall "fchmodat" (268) [priority: 65535]
    if ($syscall == 268)
        action KILL;
          # default action
            action ALLOW;
# invalid architecture action
action KILL;
#
# pseudo filter code end
#
     */

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
