#ifndef MACSCOPE_FATAL_SIGNAL_C_H
#define MACSCOPE_FATAL_SIGNAL_C_H

#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <pthread/introspection.h>

_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "Fatal signal state requires lock-free int atomics");

// All stateful entry points are called only by MCPFatalSignalReporter.swift.
static _Atomic int MacScopeFatalStateSlot = 0;
// Crash contract: ruling (b) counts only the fatal-report line, exactly one per process,
// guarded by MacScopeFatalReported. The failure-path startup and worker-entry warnings are
// diagnostics emitted before any signal and are not counted: each is fixed text, emitted at
// most once per process per cause, never from inside a signal handler, and never matching
// the fatal-report line format. The healthy path stays silent.
static atomic_flag MacScopeFatalReported = ATOMIC_FLAG_INIT;
static char MacScopeFatalBuffer[256] = {0};
static const char *const MacScopeFatalStateNames[] = {
    "starting", "openingPackage", "fingerprinting", "verifying", "binding", "ready", "failed"
};
static const char *const MacScopeFatalPhaseNames[] = {
    "load", "decode", "functionDiscovery", "listing", "jumpTables",
    "controlFlow", "dataReferences", "switchHints", "diagnostics", "rehydrate"
};
static const int MacScopeFatalSignalNumbers[] = {
    SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP, SIGABRT, SIGSYS, SIGXCPU, SIGXFSZ
};
static const char *const MacScopeFatalSignalNames[] = {
    "SIGSEGV", "SIGBUS", "SIGILL", "SIGFPE", "SIGTRAP", "SIGABRT", "SIGSYS", "SIGXCPU", "SIGXFSZ"
};
static const struct sigaction MacScopeFatalDefaultAction = {
    .sa_handler = SIG_DFL, .sa_mask = 0, .sa_flags = 0
};

enum { MacScopeFatalWriteAttemptLimit = 512 };
typedef ssize_t (*MacScopeFatalWriter)(int, const void *, size_t);

// Stateless: tests inject a writer without reaching this module's handler state.
static inline size_t MacScopeFatalWriteAll(int fd, const char *bytes, size_t count,
                                         MacScopeFatalWriter writer, unsigned maxAttempts) {
    size_t used = 0;
    for (unsigned attempt = 0; used < count && attempt < maxAttempts; ++attempt) {
        ssize_t written = writer(fd, bytes + used, count - used);
        if (written > 0) {
            if ((size_t)written > count - used) break; // Invalid injected writer.
            used += (size_t)written;
        } else if (written != -1 || (errno != EINTR && errno != EAGAIN)) {
            break;
        }
    }
    return used;
}

static inline void MacScopeFatalAppend(const char *text, char *buf, size_t cap, size_t *used) {
    while (*text && *used < cap) {
        buf[(*used)++] = *text++;
    }
}

static inline size_t MacScopeFatalSignalFormat(int signo, int slot, char *buf, size_t cap) {
    if (!buf || !cap) return 0;
    size_t used = 0;
    const char *name = "UNKNOWN";
    for (size_t i = 0; i < sizeof(MacScopeFatalSignalNumbers) / sizeof(MacScopeFatalSignalNumbers[0]); ++i) {
        if (MacScopeFatalSignalNumbers[i] == signo) { name = MacScopeFatalSignalNames[i]; break; }
    }
    MacScopeFatalAppend("MacScope MCP: terminated by signal ", buf, cap, &used);
    MacScopeFatalAppend(name, buf, cap, &used);
    MacScopeFatalAppend(" (", buf, cap, &used);
    unsigned int magnitude = (unsigned int)signo;
    if (signo < 0) {
        MacScopeFatalAppend("-", buf, cap, &used);
        magnitude = 0u - magnitude; // Defined even for INT_MIN.
    }
    char digits[sizeof(unsigned int) * 3 + 1];
    size_t count = 0;
    do {
        digits[count++] = (char)('0' + magnitude % 10);
        magnitude /= 10;
    } while (magnitude);
    while (count && used < cap) buf[used++] = digits[--count];
    MacScopeFatalAppend(") in state ", buf, cap, &used);
    if (slot >= 0 && slot < 7) {
        MacScopeFatalAppend(MacScopeFatalStateNames[slot], buf, cap, &used);
    } else if (slot >= 16 && slot < 26) {
        MacScopeFatalAppend("analyzing (phase ", buf, cap, &used);
        MacScopeFatalAppend(MacScopeFatalPhaseNames[slot - 16], buf, cap, &used);
        MacScopeFatalAppend(")", buf, cap, &used);
    } else {
        MacScopeFatalAppend("unknown", buf, cap, &used);
    }
    MacScopeFatalAppend("\n", buf, cap, &used);
    return used; // Counted bytes, not a NUL-terminated string.
}

static inline void MacScopeFatalSignalNote(int slot) {
    atomic_store_explicit(&MacScopeFatalStateSlot, slot, memory_order_relaxed);
}

static inline void MacScopeFatalSignalHandler(int signo) {
    int savedErrno = errno;
    if (!atomic_flag_test_and_set_explicit(&MacScopeFatalReported, memory_order_relaxed)) {
        int slot = atomic_load_explicit(&MacScopeFatalStateSlot, memory_order_relaxed);
        size_t count = MacScopeFatalSignalFormat(signo, slot, MacScopeFatalBuffer, sizeof(MacScopeFatalBuffer));
        (void)MacScopeFatalWriteAll(STDERR_FILENO, MacScopeFatalBuffer, count,
                                  write, MacScopeFatalWriteAttemptLimit);
    }
    errno = savedErrno;
    // Darwin does not apply SA_RESETHAND to SIGILL or SIGTRAP.
    (void)sigaction(signo, &MacScopeFatalDefaultAction, NULL);
    (void)raise(signo);
    // If still masked, return so the pending signal is delivered under SIG_DFL.
}

static inline int MacScopeInstallFatalSignalHandler(int signo, struct sigaction *previous) {
    if (signo == SIGPIPE || signo == SIGCHLD || signo == SIGKILL || signo == SIGSTOP) return 1;
    if (sigaction(signo, NULL, previous) != 0) return -1;
    if (previous->sa_handler != SIG_DFL || (previous->sa_flags & SA_SIGINFO)) return 1;
    struct sigaction action = {0};
    action.sa_handler = MacScopeFatalSignalHandler;
    action.sa_flags = SA_ONSTACK | SA_RESETHAND;
    if (sigemptyset(&action.sa_mask) != 0) return -1;
    if (sigaddset(&action.sa_mask, signo) != 0) return -1;
    for (size_t i = 0; i < sizeof(MacScopeFatalSignalNumbers) / sizeof(MacScopeFatalSignalNumbers[0]); ++i) {
        if (sigaddset(&action.sa_mask, MacScopeFatalSignalNumbers[i]) != 0) return -1;
    }
    return sigaction(signo, &action, NULL);
}

static inline int MacScopeRestoreSignalAction(int signo, const struct sigaction *previous) {
    if (signo == SIGPIPE || signo == SIGCHLD || signo == SIGKILL || signo == SIGSTOP) return 1;
    return sigaction(signo, previous, NULL);
}

static inline int MacScopeReadAlternateSignalStack(stack_t *current) {
    return sigaltstack(NULL, current);
}

static inline int MacScopeEnsureAlternateSignalStack(void) {
    stack_t current;
    if (sigaltstack(NULL, &current) != 0) return -1;
    if (!(current.ss_flags & SS_DISABLE)) return 0;
    void *memory = malloc(SIGSTKSZ);
    if (!memory) { errno = ENOMEM; return -1; }
    stack_t stack = {0};
    stack.ss_sp = memory;
    stack.ss_size = SIGSTKSZ;
    if (sigaltstack(&stack, NULL) != 0) {
        int failure = errno;
        free(memory);
        errno = failure;
        return -1;
    }
    // Thread-owned alternate stacks outlive this call and are intentionally not freed.
    return 0;
}

// Candidate only: see 1302 OPEN O1/O5. Callers serialize install/restore.
// The exchange API does not establish callback-publication or quiescence guarantees.
static _Atomic(pthread_introspection_hook_t) MacScopeThreadPrevious = NULL;
static _Atomic int MacScopeThreadFailures = 0, MacScopeThreadWarnings = 0;
static int MacScopeThreadInstalled = 0;
static _Thread_local int MacScopeThreadSawStart = 0;
_Static_assert(ATOMIC_POINTER_LOCK_FREE == 2, "Thread hook requires lock-free pointers");

static void MacScopeThreadStackHook(unsigned event, pthread_t thread, void *addr, size_t size) {
    int savedErrno = errno;
    if (event == PTHREAD_INTROSPECTION_THREAD_START) {
        if (thread != pthread_self() || MacScopeEnsureAlternateSignalStack() != 0)
            atomic_fetch_or_explicit(&MacScopeThreadFailures, 1, memory_order_relaxed);
        else
            MacScopeThreadSawStart = 1;
    }
    errno = savedErrno;
    pthread_introspection_hook_t previous =
        atomic_load_explicit(&MacScopeThreadPrevious, memory_order_acquire);
    // Preparation failure must not suppress the predecessor.
    if (previous && previous != MacScopeThreadStackHook) previous(event, thread, addr, size);
}

static inline int MacScopeInstallThreadStackHook(void) {
    if (!MacScopeThreadInstalled) {
        pthread_introspection_hook_t previous =
            pthread_introspection_hook_install(MacScopeThreadStackHook);
        if (previous == MacScopeThreadStackHook) {
            atomic_fetch_or_explicit(&MacScopeThreadFailures, 2, memory_order_relaxed);
            return -1; // Never publish a self-chain.
        }
        atomic_store_explicit(&MacScopeThreadPrevious, previous, memory_order_release);
        MacScopeThreadInstalled = 1;
    }
    return MacScopeEnsureAlternateSignalStack(); // Also covers the installing thread.
}

static inline int MacScopeRestoreThreadStackHook(void) {
    if (!MacScopeThreadInstalled) return 0;
    pthread_introspection_hook_t previous =
        atomic_load_explicit(&MacScopeThreadPrevious, memory_order_acquire);
    pthread_introspection_hook_t displaced = pthread_introspection_hook_install(previous);
    if (displaced != MacScopeThreadStackHook) {
        // Best effort only; this is NOT an atomic compare-and-restore.
        (void)pthread_introspection_hook_install(displaced);
        atomic_fetch_or_explicit(&MacScopeThreadFailures, 2, memory_order_relaxed);
        return -1;
    }
    MacScopeThreadInstalled = 0;
    // Retain predecessor storage for callbacks already in flight.
    return 0;
}

static inline int MacScopeTakeThreadStackWarnings(void) {
    int failures = atomic_load_explicit(&MacScopeThreadFailures, memory_order_relaxed);
    return failures & ~atomic_fetch_or_explicit(&MacScopeThreadWarnings, failures, memory_order_relaxed);
}

static inline int MacScopeThreadStackSawStart(void) { return MacScopeThreadSawStart; }

// C-only test predecessor, reached through the app's Swift wrappers, never CoreTests statics.
// Fixture state has process lifetime; no callback retains Swift objects or stack storage.
static _Atomic(pthread_introspection_hook_t) MacScopeProbePrevious = NULL;
static _Atomic(pthread_t) MacScopeProbeThread = NULL;
static _Atomic int MacScopeProbeCounts[4] = {0}, MacScopeProbePrepared = 0;
static _Thread_local int MacScopeProbeArm = 0;
static int MacScopeProbeActive = 0;

static inline int MacScopeProbeIndex(unsigned event) {
    switch (event) {
        case PTHREAD_INTROSPECTION_THREAD_CREATE: return 0;
        case PTHREAD_INTROSPECTION_THREAD_START: return 1;
        case PTHREAD_INTROSPECTION_THREAD_TERMINATE: return 2;
        case PTHREAD_INTROSPECTION_THREAD_DESTROY: return 3;
        default: return -1;
    }
}

static void MacScopeThreadStackProbe(unsigned event, pthread_t thread, void *addr, size_t size) {
    if (event == PTHREAD_INTROSPECTION_THREAD_CREATE && MacScopeProbeArm) {
        atomic_store_explicit(&MacScopeProbeThread, thread, memory_order_release);
        MacScopeProbeArm = 0;
    }
    if (thread == atomic_load_explicit(&MacScopeProbeThread, memory_order_acquire)) {
        int index = MacScopeProbeIndex(event);
        if (index >= 0) atomic_fetch_add_explicit(&MacScopeProbeCounts[index], 1, memory_order_relaxed);
        if (event == PTHREAD_INTROSPECTION_THREAD_START && MacScopeThreadSawStart)
            atomic_fetch_add_explicit(&MacScopeProbePrepared, 1, memory_order_relaxed);
    }
    pthread_introspection_hook_t previous =
        atomic_load_explicit(&MacScopeProbePrevious, memory_order_acquire);
    if (previous && previous != MacScopeThreadStackProbe) previous(event, thread, addr, size);
}

static inline int MacScopeBeginThreadStackProbe(void) {
    if (MacScopeThreadInstalled || MacScopeProbeActive) return -1;
    atomic_store_explicit(&MacScopeProbeThread, NULL, memory_order_relaxed);
    for (int i = 0; i < 4; ++i) atomic_store_explicit(&MacScopeProbeCounts[i], 0, memory_order_relaxed);
    atomic_store_explicit(&MacScopeProbePrepared, 0, memory_order_relaxed);
    pthread_introspection_hook_t previous =
        pthread_introspection_hook_install(MacScopeThreadStackProbe);
    if (previous == MacScopeThreadStackProbe || previous == MacScopeThreadStackHook) {
        (void)pthread_introspection_hook_install(previous);
        return -1;
    }
    atomic_store_explicit(&MacScopeProbePrevious, previous, memory_order_release);
    MacScopeProbeActive = 1;
    return 0;
}

static inline int MacScopeEndThreadStackProbe(void) {
    if (!MacScopeProbeActive) return -1;
    if (MacScopeRestoreThreadStackHook() != 0) return -1;
    pthread_introspection_hook_t previous =
        atomic_load_explicit(&MacScopeProbePrevious, memory_order_acquire);
    pthread_introspection_hook_t displaced = pthread_introspection_hook_install(previous);
    if (displaced != MacScopeThreadStackProbe) {
        (void)pthread_introspection_hook_install(displaced);
        atomic_fetch_or_explicit(&MacScopeThreadFailures, 2, memory_order_relaxed);
        return -1;
    }
    MacScopeProbeActive = 0;
    return 0;
}

static inline void MacScopeSetThreadStackProbeArmed(int armed) { MacScopeProbeArm = armed; }
static inline int MacScopeThreadStackProbeCount(unsigned event) {
    int index = MacScopeProbeIndex(event);
    return index < 0 ? -1 : atomic_load_explicit(&MacScopeProbeCounts[index], memory_order_relaxed);
}
static inline int MacScopeThreadStackProbePrepared(void) {
    return atomic_load_explicit(&MacScopeProbePrepared, memory_order_relaxed);
}

#endif
