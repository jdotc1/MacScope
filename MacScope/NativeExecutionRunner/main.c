/* Fixed launch grammar: original executable, exclusive job directory. */
#include <sys/stat.h>
#include <sys/resource.h>
#include <libproc.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <spawn.h>
#include <pwd.h>

static void fail(const char *reason) {
    fprintf(stderr, "native-runner: %s\n", reason);
    _exit(125);
}
static void canonical(const char *path, char *resolved) {
    if (!realpath(path, resolved) || strcmp(path, resolved)) fail("noncanonical path");
    /* Policy strings are authored here; reject bytes requiring SBPL escaping. */
    for (const unsigned char *p = (const unsigned char *)path; *p; ++p)
        if (*p < 32 || *p == 127 || *p == '"' || *p == '\\') fail("unsupported path byte");
}
static void limit(int resource, rlim_t value) {
    struct rlimit bound = {value, value};
    if (setrlimit(resource, &bound)) fail("resource limit unavailable");
}
static int create(int directory, const char *name) {
    int fd = openat(directory, name, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
    if (fd < 0) fail("exclusive output unavailable");
    return fd;
}
int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "--confined") == 0) {
        /* sandbox-exec runs before a debugger is attached. SETEXEC keeps the
           retained child identity; START_SUSPENDED stops the new image atomically. */
        char binary[PATH_MAX];
        canonical(argv[2], binary);
        posix_spawnattr_t attributes;
        int status = posix_spawnattr_init(&attributes);
        if (status) fail("spawn attributes unavailable");
        status = posix_spawnattr_setflags(&attributes,
            POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED);
        if (status) fail("suspended exec attributes unavailable");
        char *arguments[] = {binary, NULL};
        char *environment[] = {"PATH=/usr/bin:/bin", "LANG=C", NULL};
        pid_t replacement;
        status = posix_spawn(&replacement, binary, NULL, &attributes, arguments, environment);
        posix_spawnattr_destroy(&attributes);
        errno = status;
        fail("suspended executable replacement failed");
    }
    if (argc != 3) fail("expected executable and job directory");
    char binary[PATH_MAX], job[PATH_MAX], helper[PATH_MAX], bundle[PATH_MAX] = {0};
    canonical(argv[1], binary);
    canonical(argv[2], job);
    canonical(argv[0], helper);
    char prefix[PATH_MAX];
    struct passwd *owner = getpwuid(getuid());
    if (!owner || !owner->pw_dir) fail("work root unavailable");
    int prefixSize = snprintf(prefix, sizeof(prefix), "%s/Developer/MacScope/", owner->pw_dir);
    if (prefixSize < 0 || (size_t)prefixSize >= sizeof(prefix)
        || strncmp(job, prefix, (size_t)prefixSize)) fail("job outside work root");
    struct stat executable, directory;
    if (lstat(binary, &executable) || !S_ISREG(executable.st_mode)
        || !(executable.st_mode & S_IXUSR) || (executable.st_mode & (S_ISUID|S_ISGID)))
        fail("invalid executable");
    int root = open(job, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (root < 0 || fstat(root, &directory) || directory.st_uid != getuid()
        || (directory.st_mode & 0777) != 0700) fail("invalid job directory");

    /* Only a real enclosing .app is admitted as an additional readable tree. */
    for (char *p = binary; (p = strstr(p, ".app/")); ++p) {
        size_t length = (size_t)(p - binary) + 4;
        if (length >= sizeof(bundle)) fail("bundle path too long");
        memcpy(bundle, binary, length); bundle[length] = 0;
        struct stat info;
        if (lstat(bundle, &info) || !S_ISDIR(info.st_mode)) fail("invalid app bundle");
        break;
    }
    struct proc_bsdinfo identity;
    memset(&identity, 0, sizeof(identity));
    if (proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &identity, sizeof(identity)) != sizeof(identity))
        fail("process identity unavailable");
    int ownership = create(root, "process.json");
    if (dprintf(ownership, "{\"pid\":%d,\"startSeconds\":%llu,\"startMicroseconds\":%llu}\n",
        getpid(), (unsigned long long)identity.pbi_start_tvsec,
        (unsigned long long)identity.pbi_start_tvusec) < 0) fail("process identity write failed");
    if (close(ownership)) fail("process identity close failed");
    int out = create(root, "stdout"), err = create(root, "stderr");
    if (dup2(out, STDOUT_FILENO) < 0 || dup2(err, STDERR_FILENO) < 0) fail("output isolation failed");
    int input = open("/dev/null", O_RDONLY|O_CLOEXEC);
    if (input < 0 || dup2(input, STDIN_FILENO) < 0) fail("input isolation failed");
    if (fchdir(root)) fail("job working directory unavailable");
    /* Descriptor closure precedes target code and prevents framing-channel inheritance. */
    int descriptorCount = getdtablesize();
    if (descriptorCount < 3 || descriptorCount > 1048576) fail("descriptor limit unavailable");
    for (int fd = 3; fd < descriptorCount; ++fd) close(fd);
    limit(RLIMIT_CPU, 15); limit(RLIMIT_STACK, 8*1024*1024);
    limit(RLIMIT_FSIZE, 64*1024); limit(RLIMIT_NOFILE, 64); limit(RLIMIT_CORE, 0);
    char profile[32768], bundleRule[PATH_MAX+64] = {0};
    if (bundle[0]) {
        int b = snprintf(bundleRule, sizeof(bundleRule), "(subpath \"%s\")", bundle);
        if (b < 0 || (size_t)b >= sizeof(bundleRule)) fail("bundle policy too large");
    }
    int count = snprintf(profile, sizeof(profile),
        "(version 1)(deny default)(allow sysctl-read)"
        "(allow file-read* (literal \"/\") (subpath \"/System/Library\")"
        "(subpath \"/usr/lib\") (literal \"/dev/null\") (literal \"/dev/urandom\")"
        "(literal \"%s\") (literal \"%s\") %s)"
        "(allow file-read-metadata)"
        "(allow process-exec (literal \"%s\") (literal \"%s\"))"
        "(allow file-write* (literal \"%s/stdout\") (literal \"%s/stderr\"))",
        binary, helper, bundleRule, binary, helper, job, job);
    if (count < 0 || (size_t)count >= sizeof(profile)) fail("policy too large");
    char temporary[PATH_MAX+16];
    count = snprintf(temporary, sizeof(temporary), "TMPDIR=%s/", job);
    if (count < 0 || (size_t)count >= sizeof(temporary)) fail("temporary path too large");
    char *environment[] = {"PATH=/usr/bin:/bin", "LANG=C", temporary, NULL};
    char *arguments[] = {"sandbox-exec", "-p", profile, helper, "--confined", binary, job, NULL};
    execve("/usr/bin/sandbox-exec", arguments, environment);
    fail("confinement launch failed");
}
