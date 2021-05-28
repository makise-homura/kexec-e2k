#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <utmp.h>
#include <utmpx.h>
#include <unistd.h>
#include <sys/klog.h>
#include <sys/ioctl.h>
#include <linux/types.h>
typedef __u64 u64;
#include <asm/kexec.h>

const size_t alignment = 4096;
struct lintel_reboot_param lintel __attribute__((aligned(alignment)));

void cancel(int num, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    exit(num);
}

void check_runlevel(void)
{
    int runlevel = -1;
    struct utmpx *ut;

    setutxent();
    while ((ut = getutxent()) != NULL)
    {
        if (ut->ut_type == RUN_LVL)
        {
            runlevel = ut->ut_pid % 256 - '0';
            break;
        }
    }
    endutxent();

    if (runlevel < 0) cancel(8, "Can't get current runlevel: %s\n", errno ? strerror(errno) : "No RUN_LVL entry in utmp file");
    if (runlevel != 1) cancel(9, "You should run this only from runlevel 1, but current runlevel is %d\n", runlevel);
}

void free_lintel(void)
{
    free(lintel.image);
}

void load_lintel(const char *fname)
{
    FILE *f = fopen(fname,"r");
    if (f == NULL) cancel(1, "Can't open %s: %s\n", fname, strerror(errno));
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); cancel(2, "Can't seek lintel file: %s\n", strerror(errno)); }
    if ((lintel.image_size = ftell(f)) == -1) { fclose(f); cancel(3, "Can't get file position of lintel file: %s\n", strerror(errno)); }
    rewind(f);
    lintel.image_size += alignment ; lintel.image_size -= lintel.image_size % alignment;

    if (posix_memalign(&lintel.image, alignment, lintel.image_size)) { fclose(f); cancel(4, "Can't allocate %ld bytes for lintel file\n", lintel.image_size); }
    atexit(free_lintel);
    if (fread(lintel.image, lintel.image_size, 1, f) != 1) { fclose(f); cancel(5, "Can't read %ld bytes for lintel file: %s\n", lintel.image_size, strerror(errno)); }
    fclose(f);

    printf("Loaded lintel file: %s, %ld bytes at address %p (aligned at 0x%x), ioctl struct at %p\n", fname, lintel.image_size, lintel.image, alignment, &lintel);
}

int check_syslog(const char *marker)
{
    char buf[1001];
    memset(buf, 0, 1001);
    int len = klogctl(3, buf, 1000);
    return !strcmp(buf + len - strlen(marker), marker);
}

void remount_filesystems()
{
    FILE *f = fopen("/proc/sysrq-trigger","w");
    if (f == NULL) cancel(10, "Can't open sysrq-trigger file: %s\n", strerror(errno));
    if (fprintf(f, "u\n") < 1) { fclose(f); cancel(11, "Can't write to sysrq-trigger file: %s\n", strerror(errno)); }
    fclose(f);

    while(!check_syslog("Emergency Remount complete\n"));
}

const char *check_args(int argc, char *argv[], const char *def)
{
    if (argc > 1)
    {
        if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))
        {
            cancel(0, "Usage: %s {<path>|-h|--help}\n\t<path> is path to lintel file (default is %s)\n\t-h | --help: Print this help\n", argv[0], def);
        }
        return argv[1];
    }
    return def;
}

int open_kexec()
{
    int fd;
    if ((fd = open("/dev/kexec", O_RDONLY)) == -1) cancel(6, "Can't open kexec device: %s\n", strerror(errno));
    return fd;
}

int main(int argc, char *argv[])
{
    const char *fname = check_args(argc, argv, "/opt/mcst/lintel/bin/lintel_e8c.disk");
    check_runlevel();
    void *pbuf;
    load_lintel(fname);

    printf("Flushing filesystems...\n");
    sync();
    remount_filesystems();

    printf("Rebooting to lintel...\n");
    int kexec_fd = open_kexec();
    int rv = ioctl(kexec_fd, LINTEL_REBOOT, &lintel);

    int err = errno;
    close(kexec_fd);
    cancel(7, "Failure performing ioctl (returned %d) to start lintel: %s\nNote: you should remount everything back to rw to bring system back to work\n", rv, strerror(err));
}
