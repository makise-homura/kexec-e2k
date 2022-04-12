#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <utmp.h>
#include <utmpx.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/klog.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/types.h>
#include <linux/fb.h>
#include <pci/pci.h>
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

int con2fbmap(int tty)
{
    /* See con2fbmap by Michael J. Hammel: https://gitlab.com/pibox/con2fbmap */
    const char *fbpath = "/dev/fb0";  /* any frame buffer will do */

    int fd;
    struct fb_con2fbmap map;
    map.console = tty;

    if ((fd = open(fbpath, O_RDONLY)) == -1)
    {
        if (errno == ENOENT) return -1;
        cancel(67, "Can't open framebuffer device %s: %s\n", fbpath, strerror(errno));
    }
    if (ioctl(fd, FBIOGET_CON2FBMAP, &map))
    {
        close(fd);
        cancel(68, "Can't perform FBIOGET_CON2FBMAP ioctl: %s\n", strerror(errno));
    }
    close(fd);
    return map.framebuffer;
}

char *quick_basename(char *arg)
{
    /* We could have used libgen.h or string.h implementation, but it's unreliable which one we get. So we implement it on our own. */
    int l = strlen(arg);
    if (l == 0) return NULL;
    if (l > 0 && arg[l] == '/') arg[l] = '\0';

    char *parg = strrchr(arg, '/');
    if (parg == NULL) return arg;

    if (*++parg == '\0') return NULL;
    return parg;
}

char *quick_dirname(char *arg)
{
    int l = strlen(arg);
    if (l == 0) return NULL;
    if (l > 0 && arg[l] == '/') arg[l] = '\0';

    char *parg = strrchr(arg, '/');
    if (parg == NULL) return NULL;
    *parg = '\0';
    return arg;
}

int path_snprintf_nc(char *buf, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int sz = vsnprintf(buf, PATH_MAX, fmt, ap);
    va_end(ap);
    return (sz >= PATH_MAX) ? -1 : 0;
}

void path_snprintf(char *buf, const char *name, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int sz = vsnprintf(buf, PATH_MAX, fmt, ap);
    va_end(ap);
    if(sz >= PATH_MAX) cancel(69, "Path to %s is greater than %d bytes", name, PATH_MAX - 1);
}

void path_readlink(const char *link, char *buf)
{
    ssize_t ls = readlink(link, buf, PATH_MAX);
    if (ls == -1) cancel(69, "Can't read %s: %s\n", link, strerror(errno));
    if (ls == PATH_MAX) cancel(70, "Path linked by %s is greater than %d bytes", link, PATH_MAX - 1);
}

void read_sysfs(const char *file, char **buf, DIR *dir)
{
    int fd;
    off_t size = 4096;
    struct stat st;
    if(stat(file, &st) == -1)
    {
        int e = errno;
        if (dir) closedir(dir);
        cancel(71, "Can't stat %s: %s\n", file, strerror(e));
    }
    if(st.st_size > 0) size = st.st_size;

    if ((fd = open(file, O_RDONLY)) == -1)
    {
        int e = errno;
        if (dir) closedir(dir);
        cancel(72, "Can't open %s for reading: %s\n", file, strerror(e));
    }

    if((*buf = malloc(size + 1)) == NULL)
    {
        if (dir) closedir(dir);
        close(fd);
        cancel(73, "Can't allocate %d bytes to read %s\n", size, file);
    }
    memset(*buf, 0, size + 1);

    if (read(fd, *buf, size) < 1)
    {
        int e = errno;
        if (dir) closedir(dir);
        close(fd);
        free(*buf);
        cancel(74, "Can't read %s: %s\n", file, strerror(e));
    }
    close(fd);
}

void write_sysfs(const char *file, const char *buf)
{
    int fd;

    if ((fd = open(file, O_WRONLY)) == -1)
    {
        cancel(72, "Can't open %s for writing: %s\n", file, strerror(errno));
    }

    if (write(fd, buf, strlen(buf)) < 1)
    {
        close(fd);
        cancel(74, "Can't write %s: %s\n", file, strerror(errno));
    }
    close(fd);
}

void parse_pci_id(char *pciid, int *domain, int *bus, int *dev, int *func)
{
    char *s, *endp;
    errno = 0;

    s = strtok(pciid, ":.");
    if (s == NULL) cancel(75, "Can't recognize domain id for the bridge.\n");
    *domain = strtol(s, &endp, 16);
    if (errno || *endp) cancel(76, "Malformed domain id for the bridge.\n");

    s = strtok(NULL, ":.");
    if (s == NULL) cancel(77, "Can't recognize bus id for the bridge.\n");
    *bus = strtol(s, &endp, 16);
    if (errno || *endp) cancel(78, "Malformed bus id for the bridge.\n");

    s = strtok(NULL, ":.");
    if (s == NULL) cancel(79, "Can't recognize dev id for the bridge.\n");
    *dev = strtol(s, &endp, 16);
    if (errno || *endp) cancel(80, "Malformed dev id for the bridge.\n");

    s = strtok(NULL, ":.");
    if (s == NULL) cancel(81, "Can't recognize func id for the bridge.\n");
    *func = strtol(s, &endp, 16);
    if (errno || *endp) cancel(82, "Malformed func id for the bridge.\n");
}

void bridge_reset(char *pciid)
{
    int domain, bus, dev, func;
    parse_pci_id(pciid, &domain, &bus, &dev, &func);

    /* libpci seems to have error handling undocumented; so we skip it here. */
    struct pci_access *pacc = pci_alloc();
    pci_init(pacc);
    struct pci_dev *pdev = pci_get_dev(pacc, domain, bus, dev, func);

    uint32_t bridge_ctl = pci_read_word(pdev, 0x3E);
    pci_write_word(pdev, 0x3E, bridge_ctl | 0x40);
    usleep(10000);
    pci_write_word(pdev, 0x3E, bridge_ctl);
    usleep(500000);

    pci_free_dev(pdev);
    pci_cleanup(pacc);
}

void delete_module(const char *name)
{
    if (syscall(SYS_delete_module, name, O_NONBLOCK) == -1) cancel(83, "Can't remove module %s: %s\n", name, strerror(errno));
}

int detect_vtcon(const char *signature)
{
    DIR *pdir;
    struct dirent *pdirent;
    char *contents;

    if ((pdir = opendir("/sys/devices/virtual/vtconsole/")) == NULL) cancel(84, "Can't open vtconsole directory: %s\n", strerror(errno));

    for(;;)
    {
        errno = 0;
        pdirent = readdir(pdir);
        if (pdirent == NULL)
        {
            int e = errno;
            closedir(pdir);
            if (e) cancel(86, "Can't read vtconsole directory: %s\n", strerror(errno));
            cancel(87, "Can't find console that is %s.\n", signature);
        }

        if (pdirent->d_name[0] == '.') continue;
        char name[PATH_MAX];
        if(path_snprintf_nc(name, "/sys/class/vtconsole/%s/name", pdirent->d_name) == -1)
        {
            closedir(pdir);
            cancel(88, "Path to virtual console name is greater than %d bytes", name, PATH_MAX - 1);
        }

        read_sysfs(name, &contents, pdir);
        if (strstr(contents, signature) != NULL)
        {
            free(contents);
            break;
        }
        free(contents);
    }

    char *desired = pdirent->d_name;
    if(strncmp(desired, "vtcon", 5))
    {
        closedir(pdir);
        cancel(89, "Virtual console name %s is wrong", desired);
    }

    char *endp;
    errno = 0;
    int vtconnum = strtol(desired + 5, &endp, 10);
    if (errno || *endp)
    {
        closedir(pdir);
        cancel(90, "Malformed vtcon number in sysfs.\n");
    }

    if(closedir(pdir)) cancel(85, "Can't close vtconsole directory: %s\n", strerror(errno));
    return vtconnum;
}

void reset_fbdriver(int tty)
{
    /* Current kernels require specific adapter reset sequence to be performed before kexec. */
    int fb = con2fbmap(tty);
    if (fb == -1)
    {
        printf("No /dev/fb0 available; you might have no video adapter, running lintel is pointless in this case, but we'll try to start it anyway.\n");
        return;
    }

    int vtcon = detect_vtcon("frame buffer device");

    char fbdev[PATH_MAX];
    char pcilnk[PATH_MAX];
    char *pciid;
    char pcidev[PATH_MAX];
    char pciabsdev[PATH_MAX];
    char *pcibridge;
    char pciremove[PATH_MAX];
    char driverlnk[PATH_MAX];
    char drivermod[PATH_MAX];
    char *modname;
    char vtconbind[PATH_MAX];

    printf("Active framebuffer device is %d, active vtcon device is %d.\n", fb, vtcon);
    path_snprintf(fbdev, "PCI device link", "/sys/class/graphics/fb%d/device", fb);
    path_readlink(fbdev, pcilnk);
    pciid = quick_basename(pcilnk);

    if (!strncmp(pciid, "vga16fb", 7))
    {
        printf("Framebuffer console is %s, no need to reset.\n", pciid);
        return;
    }

    path_snprintf(pcidev, "PCI device instance directory", "/sys/bus/pci/devices/%s", pciid);
    path_readlink(pcidev, pciabsdev);
    pcibridge = quick_basename(quick_dirname(pciabsdev));
    path_snprintf(pciremove, "PCI device removal command pseudofile", "/sys/bus/pci/devices/%s/remove", pciid);
    path_snprintf(driverlnk, "PCI device driver symlink", "/sys/bus/pci/devices/%s/driver", pciid);
    path_readlink(driverlnk, drivermod);
    modname = quick_basename(drivermod);
    path_snprintf(vtconbind, "Virtual console bind command pseudofile", "/sys/class/vtconsole/vtcon%d/bind", vtcon);

    printf("Unbinding virtual console vtcon%d.\n", vtcon);
    write_sysfs(vtconbind, "0\n");

    printf("Unloading module %s.\n", modname);
    delete_module(modname);

    printf("Removing PCI device %s.\n", pciid);
    write_sysfs(pciremove, "1\n");

    printf("Performing bridge reset of %s.\n", pcibridge);
    bridge_reset(pcibridge);
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
    printf("Loaded lintel: %ld bytes at address %p (%ld bytes aligned at 0x%lx), ioctl struct at %p\n", lintel.image_size, lintel.image, aligned_size, alignment, &lintel);
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
        printf("BCD file %d: /%d, offset %ld blocks, size %ld blocks, init_size %ld blocks, checksum 0x%08x\n", i, file.tag, file.lba, file.size, file.init_size, file.checksum);

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

const char *check_args(int argc, char *argv[], const char *def, int *tty)
{
    if (argc > 1)
    {
        if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))
        {
            cancel(0, "Usage: %s [ [--tty <N>] <path> | -h | --help ]\n\t<N> active tty number (default is %d)\n\t<path> is path to lintel file (default is %s)\n\t-h | --help: Print this help\n", argv[0], *tty, def);
        }
        if (!strcmp(argv[1], "--tty"))
        {
            if (argc >= 3)
            {
                char *endp;
                errno = 0;
                *tty = strtol(argv[2], &endp, 0);
                if (errno || *endp)
                {
                    cancel(17, "Malformed tty number %s (run %s --help for usage)", argv[2], argv[0]);
                }
                return (argc == 3) ? def : argv[3];
            }
            else
            {
                cancel(15, "You must specify tty number (run %s --help for usage)", argv[0]);
            }
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
    int tty = 1;
    const char *fname = check_args(argc, argv, "/opt/mcst/lintel/bin/lintel_e8c.disk", &tty);

    #ifndef NO_IOMMU_CHECK
        check_iommu();
    #endif

    check_runlevel();

    load_lintel(fname);

    #ifndef NO_FBRESET
        printf("Resetting video driver...\n");
        reset_fbdriver(tty);
    #endif

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
