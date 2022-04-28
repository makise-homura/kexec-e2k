#define _GNU_SOURCE /* For strchrnul() */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <utmp.h>
#include <utmpx.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/klog.h>
#include <sys/ioctl.h>
#include <linux/fb.h>

typedef uint64_t u64;
#include <asm/kexec.h>

#ifndef NO_BRIDGE_RESET
#include <pci/pci.h>
#endif

const size_t alignment = 4096;

const uint64_t LINTEL_BCD_SIGNATURE = 0x012345678ABCDEF0ull;

struct lintel_reboot_param lintel __attribute__((aligned(alignment)));

struct __attribute__((packed)) xrt_BcdHeader_t
{
    uint64_t signature;
    uint32_t files_num;
    uint64_t free_lba;
};

struct __attribute__((packed)) xrt_BcdFile_t
{
    uint64_t lba;
    uint64_t size;
    uint64_t init_size;
    uint32_t tag;
    uint32_t checksum;
};

enum xrt_BcdFileTag_t
{
    PRIORITY_TAG_LINTEL,
    PRIORITY_TAG_LINTEL_OBJ,
    PRIORITY_TAG_X86BIOS,
    PRIORITY_TAG_X86BIOS_RECOVERY,
    PRIORITY_TAG_LIBRCOMP,
    PRIORITY_TAG_BCDBOOTINFO,
    PRIORITY_TAG_CODEBASE,
    PRIORITY_TAG_LOG,
    PRIORITY_TAG_VIDEOBIOS,
    PRIORITY_TAG_KEXEC_JUMPER
};

enum cancel_reasons_t
{
    C_SUCCESS = 0,
    C_FILE_OPEN = 10,
    C_FILE_SEEK,
    C_FILE_TELL,
    C_FILE_ALLOC,
    C_FILE_READ,
    C_FILE_CLOSE,
    C_DEV_OPEN = 20,
    C_DEV_IOCTL,
    C_RUNLEVEL_NONE = 25,
    C_RUNLEVEL_WRONG,
    C_BCD_HEADER = 30,
    C_BCD_FILEHEADER,
    C_BCD_ORDER,
    C_BCD_READ,
    C_BCD_NOTFOUND,
    C_BCD_SEEK,
    C_OPTARG = 40,
    C_OPTARG_LONG,
    C_TTY_WRONG,
    C_SUPER_HEADER = 45,
    C_SUPER_JUMPER,
    C_IOMMU_ENABLED = 55,
    C_IOMMU_STAT,
    C_FBDEV_OPEN = 60,
    C_FBDEV_IOCTL,
    C_FBDEV_CLOSE,
    C_FBDEV_TTYSTAT,
    C_FBDEV_TTYWRONG,
    C_RMMOD_FAULT = 65,
    C_LINK_READ = 70,
    C_LINK_LONG,
    C_PATH_LONG = 75,
    C_SYSFS_STAT = 80,
    C_SYSFS_ALLOC,
    C_SYSFS_OPENWRITE,
    C_SYSFS_WRITE,
    C_SYSFS_CLOSEWRITE,
    C_SYSFS_OPENREAD,
    C_SYSFS_READ,
    C_SYSFS_CLOSEREAD,
    C_PCI_DOMAIN_NONE = 90,
    C_PCI_DOMAIN_WRONG,
    C_PCI_BUS_NONE,
    C_PCI_BUS_WRONG,
    C_PCI_DEV_NONE,
    C_PCI_DEV_WRONG,
    C_PCI_FUNC_NONE,
    C_PCI_FUNC_WRONG,
    C_VTCON_OPENDIR = 100,
    C_VTCON_READDIR,
    C_VTCON_BINDLONG,
    C_VTCON_PATHLONG,
    C_VTCON_CLOSEDIR,
    C_GLOB_AMBIG = 110,
    C_GLOB_ALLOC,
    C_GLOB_ABORT,
    C_GLOB_NONE,
    C_GLOB_UNEXPECTED,
    C_FBGLOB_ALLOC = 120,
    C_FBGLOB_ABORT,
    C_FBGLOB_UNEXPECTED
};

struct flags_t
{
    int iommu;
    int runlevel;
    int resetfb;
    int fsflush;
    int vtunbind;
    int rmmod;
    int rmpci;
    int bridgerst;
};

struct lintelops
{
    char *cache;
    size_t cachesize;
    long fptr;

    size_t (*fread)(void *ptr, size_t size, size_t nmemb, FILE *stream);
    int (*fseek)(FILE *stream, long offset, int whence);
    long (*ftell)(FILE *stream);
    void (*rewind)(FILE *stream);
    int (*fclose)(FILE *stream);
};

#ifndef AS_INCLUDE /* When used to determine sizeofs, skip all functions */
static void cancel(int num, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    exit(num);
}

static int con2fbmap(int tty, glob_t* globbuf)
{
    /* See con2fbmap by Michael J. Hammel: https://gitlab.com/pibox/con2fbmap */
    int fd;
    struct fb_con2fbmap map;
    map.console = tty;

    if ((fd = open(globbuf->gl_pathv[0], O_RDONLY)) == -1)
    {
        globfree(globbuf);
        cancel(C_FBDEV_OPEN, "Can't open framebuffer device: %s\n", strerror(errno));
    }
    globfree(globbuf);
    if (ioctl(fd, FBIOGET_CON2FBMAP, &map)) { close(fd); cancel(C_FBDEV_IOCTL, "Can't perform FBIOGET_CON2FBMAP ioctl: %s\n", strerror(errno)); }
    if (close(fd) == -1) cancel(C_FBDEV_CLOSE, "Can't close framebuffer device: %s\n", strerror(errno));
    return map.framebuffer;
}

static char *quick_basename(char *arg)
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

static int path_snprintf_nc(char *buf, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int sz = vsnprintf(buf, PATH_MAX, fmt, ap);
    va_end(ap);
    return (sz >= PATH_MAX) ? -1 : 0;
}

static void path_snprintf(char *buf, const char *name, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int sz = vsnprintf(buf, PATH_MAX, fmt, ap);
    va_end(ap);
    if(sz >= PATH_MAX) cancel(C_PATH_LONG, "Path to %s is greater than %d bytes", name, PATH_MAX - 1);
}

static void path_readlink(const char *link, char *buf)
{
    ssize_t ls = readlink(link, buf, PATH_MAX);
    if (ls == -1) cancel(C_LINK_READ, "Can't read symbolic link %s: %s\n", link, strerror(errno));
    if (ls == PATH_MAX) cancel(C_LINK_LONG, "Path linked by %s is greater than %d bytes", link, PATH_MAX - 1);
}

static void read_sysfs(const char *file, char **buf, DIR *dir)
{
    int fd;
    off_t size = 4096;
    struct stat st;
    if(stat(file, &st) == -1)
    {
        int e = errno;
        if (dir) closedir(dir);
        cancel(C_SYSFS_STAT, "Can't stat %s: %s\n", file, strerror(e));
    }
    if(st.st_size > 0) size = st.st_size;

    if ((fd = open(file, O_RDONLY)) == -1)
    {
        int e = errno;
        if (dir) closedir(dir);
        cancel(C_SYSFS_OPENREAD, "Can't open %s for reading: %s\n", file, strerror(e));
    }

    if((*buf = malloc(size + 1)) == NULL)
    {
        if (dir) closedir(dir);
        close(fd);
        cancel(C_SYSFS_ALLOC, "Can't allocate %d bytes to read %s\n", size, file);
    }
    memset(*buf, 0, size + 1);

    if (read(fd, *buf, size) < 1)
    {
        int e = errno;
        if (dir) closedir(dir);
        close(fd);
        free(*buf);
        cancel(C_SYSFS_READ, "Can't read %s: %s\n", file, strerror(e));
    }
    if(close(fd) == -1)
    {
        int e = errno;
        if (dir) closedir(dir);
        free(*buf);
        cancel(C_SYSFS_CLOSEREAD, "Can't close %s opened for reading: %s\n", file, strerror(e));
    }
}

static void write_sysfs(const char *file, const char *buf)
{
    int fd;
    if ((fd = open(file, O_WRONLY)) == -1) cancel(C_SYSFS_OPENWRITE, "Can't open %s for writing: %s\n", file, strerror(errno));
    if (write(fd, buf, strlen(buf)) < 1) { int e = errno; close(fd); cancel(C_SYSFS_WRITE, "Can't write %s: %s\n", file, strerror(e)); }
    if(close(fd) == -1) cancel(C_SYSFS_CLOSEWRITE, "Can't close %s opened for writing: %s\n", file, strerror(errno));
}

#ifndef NO_BRIDGE_RESET
static char *quick_dirname(char *arg)
{
    int l = strlen(arg);
    if (l == 0) return NULL;
    if (l > 0 && arg[l] == '/') arg[l] = '\0';

    char *parg = strrchr(arg, '/');
    if (parg == NULL) return NULL;
    *parg = '\0';
    return arg;
}

static void parse_pci_id(char *pciid, int *domain, int *bus, int *dev, int *func)
{
    char *s, *endp;
    errno = 0;

    s = strtok(pciid, ":.");
    if (s == NULL) cancel(C_PCI_DOMAIN_NONE, "Can't recognize domain id for the bridge.\n");
    *domain = strtol(s, &endp, 16);
    if (errno || *endp) cancel(C_PCI_DOMAIN_WRONG, "Malformed domain id for the bridge.\n");

    s = strtok(NULL, ":.");
    if (s == NULL) cancel(C_PCI_BUS_NONE, "Can't recognize bus id for the bridge.\n");
    *bus = strtol(s, &endp, 16);
    if (errno || *endp) cancel(C_PCI_BUS_WRONG, "Malformed bus id for the bridge.\n");

    s = strtok(NULL, ":.");
    if (s == NULL) cancel(C_PCI_DEV_NONE, "Can't recognize dev id for the bridge.\n");
    *dev = strtol(s, &endp, 16);
    if (errno || *endp) cancel(C_PCI_DEV_WRONG, "Malformed dev id for the bridge.\n");

    s = strtok(NULL, ":.");
    if (s == NULL) cancel(C_PCI_FUNC_NONE, "Can't recognize func id for the bridge.\n");
    *func = strtol(s, &endp, 16);
    if (errno || *endp) cancel(C_PCI_FUNC_WRONG, "Malformed func id for the bridge.\n");
}

static void bridge_reset(char *pciid)
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
#endif

static void delete_module(const char *name)
{
    if (syscall(SYS_delete_module, name, O_NONBLOCK) == -1) cancel(C_RMMOD_FAULT, "Can't remove module %s: %s\n", name, strerror(errno));
}

#ifdef NO_STRCHRNUL
static char *strchrnul(const char *s, int c)
{
    char *r = strchr(s, c);
    return r ? r : (char*)&s[strlen(s)];
}
#endif

static void unbind_vtcon(const char *signature)
{
    DIR *pdir;
    if ((pdir = opendir("/sys/devices/virtual/vtconsole/")) == NULL) cancel(C_VTCON_OPENDIR, "Can't open vtconsole directory: %s\n", strerror(errno));

    char bind[PATH_MAX];
    int correct = 0, bound = 0;
    while(!correct || !bound)
    {
        errno = 0;

        struct dirent *pdirent = readdir(pdir);
        if (pdirent == NULL)
        {
            int e = errno;
            closedir(pdir);
            if (e) cancel(C_VTCON_READDIR, "Can't read vtconsole directory: %s\n", strerror(errno));
            printf ("Can't find console that is %s, no reset needed.\n", signature);
            return;
        }

        if (pdirent->d_name[0] == '.') continue;

        char name[PATH_MAX];
        if(path_snprintf_nc(name, "/sys/class/vtconsole/%s/name", pdirent->d_name) == -1)
        {
            closedir(pdir);
            cancel(C_VTCON_PATHLONG, "Path to virtual console name is greater than %d bytes", PATH_MAX - 1);
        }

        if(path_snprintf_nc(bind, "/sys/class/vtconsole/%s/bind", pdirent->d_name) == -1)
        {
            closedir(pdir);
            cancel(C_VTCON_BINDLONG, "Path to virtual console bind command pseudofile is greater than %d bytes", PATH_MAX - 1);
        }

        char *vtcon_bind;
        read_sysfs(bind, &vtcon_bind, pdir);
        bound = (vtcon_bind[0] == '1');
        free(vtcon_bind);

        char *vtcon_name;
        read_sysfs(name, &vtcon_name, pdir);
        *strchrnul(vtcon_name, '\n') = '\0';
        printf ("Console %s is %s, %s.\n", pdirent->d_name, vtcon_name, bound ? "active" : "inactive");
        correct = (strstr(vtcon_name, signature) != NULL);
        free(vtcon_name);
    }

    if(closedir(pdir)) cancel(C_VTCON_CLOSEDIR, "Can't close vtconsole directory: %s\n", strerror(errno));
    printf("Active %s is found. Unbinding...\n", signature);
    write_sysfs(bind, "0\n");
}

static void reset_fbdriver(int tty, const struct flags_t flags)
{
    /* Current kernels require specific adapter reset sequence to be performed before kexec. */

    char pcilnk[PATH_MAX];
    char *pciid;

    if(flags.vtunbind)
    {
        unbind_vtcon("frame buffer device");
    }

    if(flags.rmmod || flags.rmpci || flags.bridgerst)
    {
        if (tty < 0)
        {
            const char active_file[] = "/sys/class/tty/tty0/active";
            char *active_tty, *endp;
            struct stat st;
            if (stat(active_file, &st) != 0) cancel(C_FBDEV_TTYSTAT, "Can't stat() %s (maybe you don't have tty enabled, try -t <N> if you have): %s\n", active_file, strerror(errno));
            read_sysfs(active_file, &active_tty, NULL);
            errno = 0;
            if (!active_tty || strlen(active_tty) < 4 || strncmp(active_tty, "tty", 3) || (tty = strtol(&(active_tty[3]), &endp, 10)) <= 0 || errno || *endp != '\n')
            {
                free(active_tty);
                cancel(C_FBDEV_TTYWRONG, "Incorrect data (%s) in %s, can't autodetect active tty. Use -t <N> to specify it\n", active_tty, active_file);
            }
            free(active_tty);
        }

        glob_t globbuf;
        switch(glob("/dev/fb*", GLOB_ERR, NULL, &globbuf))
        {
            case 0:
                break;

            case GLOB_NOMATCH:
                globfree(&globbuf);
                printf("No /dev/fb* exist; you might have no video adapter, or use VGA console instead of framebuffer one.\n");
                return;

            case GLOB_NOSPACE:
                globfree(&globbuf);
                cancel(C_FBGLOB_ALLOC, "No memory looking for framebuffers %s\n");

            case GLOB_ABORTED:
                globfree(&globbuf);
                cancel(C_FBGLOB_ABORT, "Read error looking for framebuffers\n");

            default:
                globfree(&globbuf);
                cancel(C_FBGLOB_UNEXPECTED, "Unexpected error looking for framebuffers, internal result: %s\n", strerror(errno));
        }

        int fb = con2fbmap(tty, &globbuf);

        if (fb == -1)
        {
            printf("No console is mapped to frame buffer device; you might have no video adapter, or use VGA console instead of framebuffer one.\n");
            return;
        }
        printf("Active framebuffer device is %d.\n", fb);

        char fbdev[PATH_MAX];
        path_snprintf(fbdev, "PCI device link", "/sys/class/graphics/fb%d/device", fb);
        path_readlink(fbdev, pcilnk);
        pciid = quick_basename(pcilnk);

        if (!strncmp(pciid, "vga16fb", 7))
        {
            printf("Framebuffer console is %s, no need to reset.\n", pciid);
            return;
        }
    }


    if(flags.rmmod)
    {
        char driverlnk[PATH_MAX];
        char drivermod[PATH_MAX];
        char *modname;
        path_snprintf(driverlnk, "PCI device driver symlink", "/sys/bus/pci/devices/%s/driver", pciid);
        path_readlink(driverlnk, drivermod);
        modname = quick_basename(drivermod);
        printf("Unloading module %s.\n", modname);
        delete_module(modname);
    }

    #ifndef NO_BRIDGE_RESET
    /* We should determine bridge path before removing device */
    char pciabsdev[PATH_MAX];
    char *pcibridge;
    if(flags.bridgerst)
    {
        char pcidev[PATH_MAX];
        path_snprintf(pcidev, "PCI device instance directory", "/sys/bus/pci/devices/%s", pciid);
        path_readlink(pcidev, pciabsdev);
        pcibridge = quick_basename(quick_dirname(pciabsdev));
    }
    #endif

    if(flags.rmpci)
    {
        char pciremove[PATH_MAX];
        path_snprintf(pciremove, "PCI device removal command pseudofile", "/sys/bus/pci/devices/%s/remove", pciid);
        printf("Removing PCI device %s.\n", pciid);
        write_sysfs(pciremove, "1\n");
    }

    #ifndef NO_BRIDGE_RESET
    if(flags.bridgerst)
    {
        printf("Performing bridge reset of %s.\n", pcibridge);
        bridge_reset(pcibridge);
    }
    #endif
}

static void check_iommu(void)
{
    /* Current kernels don't allow lintel to detect devices if IOMMU is enabled. */
    struct stat st;
    if (stat("/sys/class/iommu", &st) != 0) cancel(C_IOMMU_STAT, "Can't stat() /sys/class/iommu directory (probably you have very old kernel): %s\n", strerror(errno));
    if (lstat("/sys/class/iommu/iommu0", &st) == 0) cancel(C_IOMMU_ENABLED, "IOMMU is enabled, and current kernels don't support kexec to lintel in this case. Reboot with iommu=0 kernel parameter\n");
}

static void check_runlevel(void)
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

    if (runlevel < 0) cancel(C_RUNLEVEL_NONE, "Can't get current runlevel: %s\n", errno ? strerror(errno) : "No RUN_LVL entry in utmp file");
    if (runlevel != 1) cancel(C_RUNLEVEL_WRONG, "You should run this only from runlevel 1, but current runlevel is %d\n", runlevel);
}

static void free_lintel(void)
{
    free(lintel.image);
}

static void read_lintel(struct lintelops *l, FILE *f, size_t realsize)
{
    lintel.image_size = realsize; /* Note: this should EXACTLY match the lintel binary size, because it is used to calculate jump address (mcstbug#133402 comment 38) */
    size_t aligned_size = realsize + alignment; aligned_size -= aligned_size % alignment;
    if (posix_memalign(&lintel.image, alignment, aligned_size)) { l->fclose(f); cancel(C_FILE_ALLOC, "Can't allocate %ld bytes for lintel file of %ld bytes\n", aligned_size, lintel.image_size); }
    atexit(free_lintel);
    if (l->fread(lintel.image, lintel.image_size, 1, f) != 1) { l->fclose(f); cancel(C_FILE_READ, "Can't read %ld bytes for lintel file, file might be truncated\n", lintel.image_size); }
    printf("Loaded lintel: %ld bytes at address %p (%ld bytes aligned at 0x%lx), ioctl struct at %p\n", lintel.image_size, lintel.image, aligned_size, alignment, &lintel);
    if(l->fclose(f)) cancel(C_FILE_CLOSE, "Can't close lintel file\n");
}

static struct xrt_BcdHeader_t bcd_check_files(struct lintelops *l, FILE *f)
{
    if (l->fseek(f, 512, SEEK_SET) != 0) { l->fclose(f); cancel(C_BCD_SEEK, "Can't seek to possible header of file: %s\n", strerror(errno)); }
    struct xrt_BcdHeader_t header;
    if (l->fread(&header, sizeof(header), 1, f) != 1) { l->fclose(f); cancel(C_BCD_HEADER, "Can't read header of lintel file, file might be truncated\n"); }
    if (header.signature != LINTEL_BCD_SIGNATURE) header.files_num = -1;
    return header;
}

static void patch_jumper_info(const struct xrt_BcdFile_t super_file)
{
    printf("BCD file contains kexec jumper, patching the header.\n");

    struct xrt_BcdHeader_t *subheader = (struct xrt_BcdHeader_t*)((char*)lintel.image + (super_file.init_size - 1) * 512); /* BCD map should be located in the last sector of lintel file */
    if (subheader->signature != LINTEL_BCD_SIGNATURE) cancel(C_SUPER_HEADER, "Can't find BCD signature in super file\n");
    struct xrt_BcdFile_t *files = (struct xrt_BcdFile_t*)((char*)subheader + sizeof(struct xrt_BcdHeader_t));
    for (uint32_t i = 0; i < subheader->files_num; ++i)
    {
        if ( files[i].tag == PRIORITY_TAG_KEXEC_JUMPER )
        {
            files[i].lba = super_file.lba;
            files[i].size = super_file.size;
            return;
        }
    }
    cancel(C_SUPER_JUMPER, "Can't find kexec jumper in super file\n");
}

static void load_bcd_lintel(struct lintelops *l, FILE *f, const struct xrt_BcdHeader_t header)
{
    printf ("File is BCD container (%d files).\n", header.files_num);

    struct xrt_BcdFile_t super_file = {0, 0, 0, 0, 0};
    for (uint32_t i = 0; i < header.files_num; ++i)
    {
        struct xrt_BcdFile_t file;
        if (l->fread(&file, sizeof(file), 1, f) != 1) { l->fclose(f); cancel(C_BCD_FILEHEADER, "Can't read file %d header of BCD file, file might be truncated\n"); }
        printf("BCD file %d: /%d, offset %ld blocks, size %ld blocks, init_size %ld blocks, checksum 0x%08x\n", i, file.tag, file.lba, file.size, file.init_size, file.checksum);

        if (file.tag == PRIORITY_TAG_LINTEL)
        {
            if (i != 0) { l->fclose(f); cancel(C_BCD_ORDER, "Lintel file must be the first one in BCD\n"); }
            if (file.size > file.init_size) { l->fclose(f); cancel(C_BCD_READ, "Can't read lintel file from BCD file: file is uninitialized\n"); }
            super_file.tag = file.tag;
            super_file.lba = file.lba;
            super_file.init_size = file.size; /* Save for future patching in case of kexec jumper exists */
            super_file.size = file.size;
        }
        if (file.tag == PRIORITY_TAG_KEXEC_JUMPER)
        {
            super_file.tag = file.tag;
            super_file.size = header.free_lba - super_file.lba;
            break;
        }
    }
    if (!super_file.size) { l->fclose(f); cancel(C_BCD_NOTFOUND, "Can't find lintel file in BCD file\n"); }

    if (l->fseek(f, 512 * super_file.lba, SEEK_SET) != 0) { l->fclose(f); cancel(C_BCD_SEEK, "Can't seek to start of lintel binary in BCD file: %s\n", strerror(errno)); }
    read_lintel(l, f, 512 * super_file.size);
    if (super_file.tag == PRIORITY_TAG_KEXEC_JUMPER) patch_jumper_info(super_file);
}

static void load_raw_lintel(struct lintelops *l, FILE *f)
{
    size_t realsize;
    printf ("File seems to be raw lintel image.\n");
    if (l->fseek(f, 0, SEEK_END) != 0) { l->fclose(f); cancel(C_FILE_SEEK, "Can't seek lintel file: %s\n", strerror(errno)); }
    if ((realsize = l->ftell(f)) == -1) { l->fclose(f); cancel(C_FILE_TELL, "Can't get file position of lintel file: %s\n", strerror(errno)); }
    l->rewind(f);
    read_lintel(l, f, realsize);
}

size_t stdin_fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    struct lintelops* l = (struct lintelops*)stream;
    size_t actual_bytes = size * nmemb;
    size_t newcachesize = l->fptr + actual_bytes;
    if (l->cachesize < newcachesize)
    {
        char *newcache = realloc(l->cache, newcachesize);
        if(!newcache) return 0;
        l->cache = newcache;
        l->cachesize += fread(l->cache + l->cachesize, 1, newcachesize - l->cachesize, stdin);
        actual_bytes = l->cachesize - l->fptr;
    }
    if(ptr && actual_bytes) memcpy(ptr, l->cache + l->fptr, actual_bytes);
    l->fptr += actual_bytes;
    return actual_bytes / size;
}

int stdin_fseek(FILE *stream, long offset, int whence)
{
    switch(whence)
    {
        case SEEK_SET:
            ((struct lintelops*)stream)->fptr = offset;
            break;

        case SEEK_CUR:
            ((struct lintelops*)stream)->fptr += offset;
            break;

        case SEEK_END:
            /* Read by 4k blocks till the end to determine size */
            while (((struct lintelops*)stream)->fread(NULL, 4096, 1, stream) > 0);
            break;

        default:
            errno = EINVAL;
            return -1;
    }
    return 0;
}


long stdin_ftell(FILE *stream)
{
    return ((struct lintelops*)stream)->fptr;
}

void stdin_rewind(FILE *stream)
{
    ((struct lintelops*)stream)->fptr = 0;
}

int stdin_fclose(FILE *stream)
{
    /* After fclose(), next reads from stdin would perform as if a new file was opened */
    free(((struct lintelops*)stream)->cache);
    ((struct lintelops*)stream)->cachesize = 0;
    ((struct lintelops*)stream)->cache = NULL;
    ((struct lintelops*)stream)->fptr = 0;
    return 0;
}

static void load_lintel(const char *fname)
{
    FILE *f;
    struct lintelops l = { NULL, 0, 0, fread, fseek, ftell, rewind, fclose };
    if(strcmp(fname, "-"))
    {
        /* May be undefined in non-POSIX environments; then we don't expand tilde. */
        #ifndef GLOB_TILDE
            #define GLOB_TILDE 0
        #endif

        printf("Requested lintel path: %s\n", fname);
        glob_t globbuf;
        switch(glob(fname, GLOB_ERR | GLOB_TILDE, NULL, &globbuf))
        {
            case 0:
                if (globbuf.gl_pathc != 1)
                {
                    globfree(&globbuf);
                    cancel(C_GLOB_AMBIG, "Ambiguous pattern %s matching %d files\n", fname, globbuf.gl_pathc);
                }
                break;

            case GLOB_NOSPACE:
                globfree(&globbuf);
                cancel(C_GLOB_ALLOC, "No memory globbing %s\n", fname);

            case GLOB_ABORTED:
                globfree(&globbuf);
                cancel(C_GLOB_ABORT, "Read error while globbing %s\n", fname);

            case GLOB_NOMATCH:
                globfree(&globbuf);
                cancel(C_GLOB_NONE, "No files found matching %s\n", fname);

            default:
                globfree(&globbuf);
                cancel(C_GLOB_UNEXPECTED, "Unexpected error globbing %s, internal result: %s\n", fname, strerror(errno));
        }

        f = fopen(globbuf.gl_pathv[0],"r");
        if (f == NULL) { globfree(&globbuf); cancel(C_FILE_OPEN, "Can't open %s: %s\n", fname, strerror(errno)); }
        printf("Loading lintel from %s:\n", globbuf.gl_pathv[0]);
        globfree(&globbuf);
    }
    else
    {
        printf("Piping lintel from standard input\n");
        f = (FILE*)&l;
        l.fread = stdin_fread;
        l.fseek = stdin_fseek;
        l.ftell = stdin_ftell;
        l.rewind = stdin_rewind;
        l.fclose = stdin_fclose;
    }

    struct xrt_BcdHeader_t header = bcd_check_files(&l, f);
    if (header.files_num == -1) load_raw_lintel(&l, f);
    else load_bcd_lintel(&l, f, header);
}

static int check_syslog(const char *marker)
{
    char buf[1001];
    memset(buf, 0, 1001);
    int len = klogctl(3, buf, 1000);
    return strstr(buf, marker) != NULL;
}

static void remount_filesystems()
{
    write_sysfs("/proc/sys/kernel/printk","7\n");
    write_sysfs("/proc/sysrq-trigger","u\n");
    while(!check_syslog("Emergency Remount complete\n"));
}

static void usage(const char *argv0, const char *def)
{
    printf("Usage:\n");
    printf("    %s [OPTIONS] [FILE]\n\n", argv0);
    printf("    FILE:             Lintel file to start (may be a plain lintel starter, BCD image, or a BCD image with kexec jumper)\n");
    printf("                      Wildcards are supported (to prevent shell expansion, put the argument in quotes). Only one file should fit the pattern then.\n");
    printf("                      If not specified, %s is loaded. Use a single dash to load from standard input\n", def);
    printf("    OPTIONS:\n");
    printf("        -h | --help:  Show this help and exit\n");
    #ifndef NO_BRIDGE_RESET
    printf("        -t | --tty N: Reset framebuffer device associated with ttyN instead of currently active one (has no effect if -b, or all three of -M, -P, and -B are given)\n");
    #else
    printf("        -t | --tty N: Reset framebuffer device associated with ttyN instead of currently active one (has no effect if -b, or both -M and -P are given)\n");
    #endif
    printf("        -i:           Don't check that IOMMU is off\n");
    printf("        -r:           Don't check current runlevel\n");
    printf("        -b:           Don't reset current framebuffer device\n");
    printf("        -f:           Don't sync, flush, and remount-read-only filesystems\n");
    printf("        -V:           Don't unbing currently active vtconsole (has no effect if -b is given)\n");
    printf("        -M:           Don't unload module bound to PCI Express device implementing current framebuffer (has no effect if -b is given)\n");
    printf("        -P:           Don't remove PCI Express device implementing current framebuffer (has no effect if -b is given)\n");
    #ifndef NO_BRIDGE_RESET
    printf("        -B:           Don't reset PCI bridge associated with PCI Express device implementing current framebuffer (has no effect if -b is given)\n");
    #else
    printf("        -B:           Ignored (this build does never reset PCI bridge associated with PCI Express device implementing current framebuffer)\n");
    #endif
    exit(C_SUCCESS);
}

static const char *check_args(int argc, char * const argv[], const char *def, int *tty, struct flags_t *flags)
{
    for(;;)
    {
        int opt = getopt(argc, argv, "h-:t:irbfVMPB");
        if(opt == -1)
        {
            return (optind >= argc) ? def : argv[optind];
        }

        char *endp;
        switch(opt)
        {
            case 'i':
                flags->iommu = 0;
                break;

            case 'r':
                flags->runlevel = 0;
                break;

            case 'b':
                flags->resetfb = 0;
                break;

            case 'f':
                flags->fsflush = 0;
                break;

            case 'V':
                flags->vtunbind = 0;
                break;

            case 'M':
                flags->rmmod = 0;
                break;

            case 'P':
                flags->rmpci = 0;
                break;

            case 'B':
                flags->bridgerst = 0;
                break;

            case '?':
                cancel(C_OPTARG, "Run %s --help for usage\n", argv[0]);

            case 'h':
                usage(argv[0], def);

            case '-':
                if(!strcmp(optarg, "help")) usage(argv[0], def);
                if(strcmp(optarg, "tty")) cancel(C_OPTARG_LONG, "%s: incorrect long option -- '%s'\nRun %s --help for usage\n", argv[0], optarg, argv[0]);
                if(optind >= argc) cancel(C_OPTARG, "%s: option requires an argument -- '--tty'\nRun %s --help for usage\n", argv[0], argv[0]);
                optarg = argv[optind++];

            case 't':
                errno = 0;
                *tty = strtol(optarg, &endp, 0);
                if (errno || *endp || *tty < 0)
                {
                    cancel(C_TTY_WRONG, "%s: malformed tty number %s\nRun %s --help for usage)\n", argv[0], optarg, argv[0]);
                }
        }
    }
}

static int open_kexec()
{
    int fd;
    if ((fd = open("/dev/kexec", O_RDONLY)) == -1) cancel(C_DEV_OPEN, "Can't open kexec device: %s\n", strerror(errno));
    return fd;
}

int main(int argc, char *argv[])
{
    int tty = -1;
    struct flags_t flags = { 1, 1, 1, 1, 1, 1, 1, 1 };
    const char *fname = check_args(argc, argv, "/opt/mcst/lintel/bin/lintel_*.disk", &tty, &flags);

    if (flags.iommu)
    {
        check_iommu();
    }

    if (flags.runlevel)
    {
        check_runlevel();
    }

    load_lintel(fname);

    if (flags.resetfb)
    {
        printf("Resetting video driver...\n");
        reset_fbdriver(tty, flags);
    }

    if (flags.fsflush)
    {
        printf("Flushing filesystems...\n");
        sync();
        remount_filesystems();
    }

    printf("Rebooting to lintel...\n");
    int kexec_fd = open_kexec();
    int rv = ioctl(kexec_fd, LINTEL_REBOOT, &lintel);
    int err = errno;
    close(kexec_fd);
    cancel(C_DEV_IOCTL, "Failure performing ioctl (returned %d) to start lintel: %s\n", rv, strerror(err));

    if (flags.fsflush)
    {
        printf("Note: you should at least remount everything back to rw to bring system back to work\n");
    }
}
#endif
