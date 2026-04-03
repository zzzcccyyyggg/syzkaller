// barrier_runner.c - Fork-exec barrier runner for KCSAN race detection
// Compiles two syzkaller programs separately, then runs them concurrently
// with shared-memory futex synchronization and adaptive timing control.
//
// Usage: ./barrier_runner <prog0_bin> <prog1_bin> [repeat] [delay_us] [offset_us] [udelay_task]
//
// Parameters:
//   prog0_bin    Path to compiled syzkaller program 0
//   prog1_bin    Path to compiled syzkaller program 1
//   repeat       Number of iterations (default: 100)
//   delay_us     Legacy delay before prog1 (default: 0)
//   offset_us    Timing offset between prog0 and prog1 start:
//                  >0: prog1 starts offset_us AFTER prog0
//                  <0: prog0 starts |offset_us| AFTER prog1
//                  =0: simultaneous (default)
//   udelay_task  KCSAN watchpoint window in microseconds (default: 0 = don't change)

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// Shared barrier state in shared memory
struct barrier_state {
    volatile int32_t counter;
    volatile int32_t generation;
};

static struct barrier_state* barrier;

static void barrier_init(void)
{
    barrier = (struct barrier_state*)mmap(
        NULL, sizeof(struct barrier_state),
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (barrier == MAP_FAILED) {
        perror("mmap barrier");
        exit(1);
    }
    barrier->counter = 0;
    barrier->generation = 0;
}

static void barrier_wait(void)
{
    int32_t gen = barrier->generation;
    int32_t val = __sync_add_and_fetch(&barrier->counter, 1);
    if (val < 2) {
        // Spin-wait for the other process (tight loop for minimum latency)
        while (barrier->counter < 2) {
            // Brief yield to avoid pure spin on single-core
            sched_yield();
        }
    }
    // Both arrived - proceed
}

static void barrier_reset(void)
{
    barrier->counter = 0;
    barrier->generation++;
    __sync_synchronize();
}

// Tune KCSAN runtime parameters for targeted detection.
// With ASSERT_EXCLUSIVE_* filtered in core.c and compiler instrumentation
// disabled (CFLAGS_KCSAN:=), only our manual __kcsan_check_access() calls
// trigger watchpoints. skip_watch=0 means EVERY call sets up a watchpoint.
static void kcsan_tune(int udelay_task)
{
    int fd;
    // Set skip_watch=0: every __kcsan_check_access() sets up a watchpoint
    fd = open("/sys/module/kcsan/parameters/skip_watch", O_WRONLY);
    if (fd >= 0) {
        write(fd, "0", 1);
        close(fd);
    }
    // Set report_once_in_ms=0: report every race
    fd = open("/sys/module/kcsan/parameters/report_once_in_ms", O_WRONLY);
    if (fd >= 0) {
        write(fd, "0", 1);
        close(fd);
    }
    // Set the watchpoint window duration (microseconds).
    // Larger window = more likely to catch non-overlapping accesses
    // but also more CPU overhead / slowdown.
    if (udelay_task > 0) {
        char buf[32];
        int len = snprintf(buf, sizeof(buf), "%d", udelay_task);
        fd = open("/sys/module/kcsan/parameters/udelay_task", O_WRONLY);
        if (fd >= 0) {
            write(fd, buf, len);
            close(fd);
            printf("[barrier-runner] udelay_task set to %d us\n", udelay_task);
        }
    }
}

// High-resolution sleep for microseconds
static void precise_usleep(int us)
{
    if (us <= 0)
        return;
    struct timespec ts;
    ts.tv_sec = us / 1000000;
    ts.tv_nsec = (us % 1000000) * 1000L;
    nanosleep(&ts, NULL);
}

static void usage(const char* prog)
{
    fprintf(stderr,
        "Usage: %s <prog0_bin> <prog1_bin> [repeat] [delay_us] [offset_us] [udelay_task]\n"
        "\n"
        "  prog0_bin     Path to compiled syzkaller program 0\n"
        "  prog1_bin     Path to compiled syzkaller program 1\n"
        "  repeat        Number of iterations (default: 100)\n"
        "  delay_us      Legacy delay before prog1 (default: 0)\n"
        "  offset_us     Start-time offset between prog0/prog1:\n"
        "                  >0: prog1 starts offset_us AFTER prog0\n"
        "                  <0: prog0 starts |offset_us| AFTER prog1\n"
        "                  =0: simultaneous start (default)\n"
        "  udelay_task   KCSAN watchpoint window in us (0=keep default)\n",
        prog);
    exit(1);
}

int main(int argc, char** argv)
{
    if (argc < 3)
        usage(argv[0]);

    const char* prog0 = argv[1];
    const char* prog1 = argv[2];
    int repeat   = argc > 3 ? atoi(argv[3]) : 100;
    int delay_us = argc > 4 ? atoi(argv[4]) : 0;
    int offset_us   = argc > 5 ? atoi(argv[5]) : 0;
    int udelay_task = argc > 6 ? atoi(argv[6]) : 0;

    // Verify binaries exist
    if (access(prog0, X_OK) != 0) {
        fprintf(stderr, "Error: %s not found or not executable\n", prog0);
        exit(1);
    }
    if (access(prog1, X_OK) != 0) {
        fprintf(stderr, "Error: %s not found or not executable\n", prog1);
        exit(1);
    }

    printf("[barrier-runner] prog0=%s prog1=%s repeat=%d delay_us=%d offset_us=%d udelay_task=%d\n",
           prog0, prog1, repeat, delay_us, offset_us, udelay_task);

    kcsan_tune(udelay_task);
    barrier_init();

    // Install SIGCHLD handler to avoid zombie accumulation
    signal(SIGCHLD, SIG_DFL);

    int kcsan_detected = 0;

    for (int iter = 0; iter < repeat; iter++) {
        barrier_reset();

        pid_t pid1 = fork();
        if (pid1 < 0) {
            perror("fork");
            exit(1);
        }

        if (pid1 == 0) {
            // Child 1: wait at barrier, then exec prog1
            barrier_wait();
            // If offset > 0, prog1 starts late (after prog0)
            if (offset_us > 0)
                precise_usleep(offset_us);
            // Legacy delay (backward compat)
            if (delay_us > 0)
                usleep(delay_us);
            execl(prog1, prog1, NULL);
            perror("execl prog1");
            _exit(1);
        }

        pid_t pid0 = fork();
        if (pid0 < 0) {
            perror("fork");
            kill(pid1, SIGKILL);
            waitpid(pid1, NULL, 0);
            exit(1);
        }

        if (pid0 == 0) {
            // Child 0: wait at barrier, then exec prog0
            barrier_wait();
            // If offset < 0, prog0 starts late (after prog1)
            if (offset_us < 0)
                precise_usleep(-offset_us);
            execl(prog0, prog0, NULL);
            perror("execl prog0");
            _exit(1);
        }

        // Parent: wait for both children with timeout
        int status0, status1;
        int timeout_count = 0;
        pid_t waited;

        // Use alarm for timeout
        alarm(30); // 30 second timeout per iteration

        waited = waitpid(pid0, &status0, 0);
        if (waited < 0 && errno == EINTR) {
            kill(pid0, SIGKILL);
            kill(pid1, SIGKILL);
            waitpid(pid0, NULL, 0);
            waitpid(pid1, NULL, 0);
            continue;
        }

        waited = waitpid(pid1, &status1, 0);
        if (waited < 0 && errno == EINTR) {
            kill(pid1, SIGKILL);
            waitpid(pid1, NULL, 0);
            continue;
        }

        alarm(0); // Cancel alarm

        if ((iter + 1) % 10 == 0) {
            printf("[barrier-runner] Completed iteration %d/%d (offset=%dus, udelay=%d)\n",
                   iter + 1, repeat, offset_us, udelay_task);
        }
    }

    printf("[barrier-runner] Done. %d iterations completed.\n", repeat);
    return 0;
}
