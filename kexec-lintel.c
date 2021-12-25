#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <utmp.h>
#include <utmpx.h>
#include <unistd.h>
#include <sys/stat.h>
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

void check_iommu(void)
{
    /* Current kernels don't allow lintel to detect devices if IOMMU is enabled. */
    struct stat st;
    if (stat("/sys/class/iommu", &st) != 0) cancel(61, "Can't stat() /sys/class/iommu directory (probably you have very old kernel): %s\n", strerror(errno));
    if (lstat("/sys/class/iommu/iommu0", &st) == 0) cancel(62, "IOMMU is enabled, and current kernels don't support kexec to lintel in this case. Reboot with iommu=0 kernel parameter\n");
}

void check_fbdriver(void)
{
    /* Current kernels don't allow lintel to run VGA BIOS from video adapter ROM if native driver is activated. */
    char buf[4097];
    memset(buf, 0, 4097);
    FILE *f = fopen("/proc/fb","r");
    if (f == NULL) cancel(63, "Can't open /proc/fb to get current framebuffer: %s\n", strerror(errno));
    if (fread(buf, 1, 4096, f) < 1) { fclose(f); cancel(64, "Empty /proc/fb, you might have no video adapter, running lintel is pointless in this case\n"); }
    fclose(f);
    if(strchr(buf, '\n') != strrchr(buf, '\n')) cancel(65, "Too many framebuffers in /proc/fb, probably you have native driver loaded, which is not supported\n");
    if(strcmp("0 VGA16 VGA\n", buf)) cancel(66, "Framebuffer 0 should be VGA16 VGA, but it is wrong: %s", buf);
}

void check_runlevel(void)
{
    /* For the sake of not rebooting fully running system, restrict to runlevel 1 only. We suppose nothing that may leave garbage in filesystem is running there. */
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

void read_lintel(FILE *f, size_t realsize)
{
    lintel.image_size = realsize; /* Note: this should EXACTLY match the lintel binary size, because it is used to calculate jump address (mcstbug#133402 comment 38) */
    size_t aligned_size = realsize + alignment; aligned_size -= aligned_size % alignment;
    if (posix_memalign(&lintel.image, alignment, aligned_size)) { fclose(f); cancel(4, "Can't allocate %ld bytes for lintel file of %ld bytes\n", aligned_size, lintel.image_size); }
    atexit(free_lintel);
    if (fread(lintel.image, lintel.image_size, 1, f) != 1) { fclose(f); cancel(5, "Can't read %ld bytes for lintel file, file might be truncated\n", lintel.image_size); }
    printf("Loaded lintel: %ld bytes at address %p (%ld bytes aligned at 0x%x), ioctl struct at %p\n", lintel.image_size, lintel.image, aligned_size, alignment, &lintel);
}

int bcd_check_files(FILE *f)
{
    if (fseek(f, 512, SEEK_SET) != 0) { fclose(f); cancel(14, "Can't seek to possible header of file: %s\n", strerror(errno)); }
    struct __attribute__((packed))
    {
        uint64_t signature;
        uint32_t files_num;
        uint64_t free_lba;
    } header;
    if (fread(&header, sizeof(header), 1, f) != 1) { fclose(f); cancel(10, "Can't read header of lintel file, file might be truncated\n"); }
    if (header.signature == 0x012345678ABCDEF0ull) return header.files_num;
    return -1;
}

void load_bcd_lintel(FILE *f, int files)
{
    printf ("File is BCD container (%d files).\n", files);

    for (int i = 0; i < files; ++i)
    {

        struct __attribute__((packed)) xrt_BcdFile_t
        {
            uint64_t lba;
            uint64_t size;
            uint64_t init_size;
            uint32_t tag;
            uint32_t checksum;
        } file;
        if (fread(&file, sizeof(file), 1, f) != 1) { fclose(f); cancel(11, "Can't read file %d header of BCD file, file might be truncated\n"); }
        printf("BCD file %d: /%d, offset %d blocks, size %d blocks, init_size %d blocks, checksum 0x%08x\n", i, file.tag, file.lba, file.size, file.init_size, file.checksum);

        if (file.tag == 0) /* 0 is the tag of Lintel binary */
        {
            if (file.size > file.init_size) { fclose(f); cancel(13, "Can't read lintel file from BCD file: file is uninitialized\n"); }
            if (fseek(f, 512 * file.lba, SEEK_SET) != 0) { fclose(f); cancel(14, "Can't seek to start of lintel binary in BCD file: %s\n", strerror(errno)); }
            read_lintel(f, 512 * file.size);
            return;
        }
    }
    fclose(f); cancel(12, "Can't find lintel file in BCD file\n");
}

void load_raw_lintel(FILE *f)
{
    size_t realsize;
    printf ("File seems to be raw lintel image.\n");
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); cancel(2, "Can't seek lintel file: %s\n", strerror(errno)); }
    if ((realsize = ftell(f)) == -1) { fclose(f); cancel(3, "Can't get file position of lintel file: %s\n", strerror(errno)); }
    rewind(f);
    read_lintel(f, realsize);
}

void load_lintel(const char *fname)
{
    FILE *f = fopen(fname,"r");
    if (f == NULL) cancel(1, "Can't open %s: %s\n", fname, strerror(errno));
    printf("Loading lintel from %s:\n", fname);

    int files = bcd_check_files(f);
    if (files == -1) load_raw_lintel(f);
    else load_bcd_lintel(f, files);

    fclose(f);
}

int check_syslog(const char *marker)
{
    char buf[1001];
    memset(buf, 0, 1001);
    int len = klogctl(3, buf, 1000);
    return strstr(buf, marker) != NULL;
}

void remount_filesystems()
{
    FILE *f = fopen("/proc/sysrq-trigger","w");
    if (f == NULL) cancel(10, "Can't open sysrq-trigger file: %s\n", strerror(errno));
    if (fprintf(f, "u\n") < 1) { fclose(f); cancel(11, "Can't write to sysrq-trigger file\n"); }
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
    check_iommu();
    check_fbdriver();
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
