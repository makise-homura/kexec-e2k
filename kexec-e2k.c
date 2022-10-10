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
#include <sys/sysmacros.h>
#include <sys/mount.h>
#include <sys/klog.h>
#include <sys/ioctl.h>
#include <linux/fb.h>

typedef uint64_t u64;
#include <asm/kexec.h>

const size_t alignment = 4096;

const uint64_t LINTEL_BCD_SIGNATURE = 0x012345678ABCDEF0ull;

struct lintel_reboot_param lintel __attribute__((aligned(alignment)));
struct kexec_reboot_param kernel __attribute__((aligned(alignment)));
char kcmdline[COMMAND_LINE_SIZE];

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
    C_NVRAM_OPEN = 3,
    C_NVRAM_SEEK,
    C_NVRAM_TELL,
    C_NVRAM_SIZE,
    C_NVRAM_READ,
    C_NVRAM_CLOSE,
    C_FILE_OPEN_IMAGE = 10,
    C_FILE_SEEK = 11,
    C_FILE_TELL,
    C_FILE_ALLOC,
    C_FILE_READ,
    C_FILE_CLOSE,
    C_DEV_OPEN = 20,
    C_DEV_IOCTL,
    C_MOUNTS_STAT = 22,
    C_MOUNTS_MOUNT,
    C_RUNLEVEL_NONE = 25,
    C_RUNLEVEL_WRONG,
    C_RUNLEVEL_FAIL,
    C_BCD_HEADER = 30,
    C_BCD_FILEHEADER,
    C_BCD_ORDER,
    C_BCD_READ,
    C_BCD_NOTFOUND,
    C_BCD_SEEK,
    C_OPTARG = 40,
    C_OPTARG_LONG,
    C_OPTARG_WRONG_TTY,
    C_OPTARG_WRONG_DISK,
    C_SUPER_HEADER = 45,
    C_SUPER_JUMPER,
    C_OPTARG_WRONG_ETHTYPE = 47,
    C_OPTARG_WRONG_ETHNUM,
    C_VGA_PCI = 50,
    C_LINUX_INITRD_LONG = 51,
    C_LINUX_CMDLINE_LONG,
    C_LINUX_RESCMDLINE_LONG,
    C_LINUX_OPEN_INITRD,
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
    C_DISKDEV_NONATA = 76,
    C_DISKDEV_WRONGPORT,
    C_DISKDEV_WRONGNODE,
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
    C_BRGLOB_SYSFS = 115,
    C_BRGLOB_ALLOC,
    C_BRGLOB_ABORT,
    C_BRGLOB_UNEXPECTED,
    C_FBGLOB_ALLOC = 120,
    C_FBGLOB_ABORT,
    C_FBGLOB_UNEXPECTED
};

struct flags_t
{
    int mounts;
    int iommu;
    int runlevel;
    int resetfb;
    int fsflush;
    int vtunbind;
    int rmmod;
    int rmpci;
    int kexec;
    int untrusted;
    int setvideo;
    int askfordisk;
    int chkdisknode;
    int noinitrd;
    int cmdline;
    int iskernel;
    int defethnum;
    int ethnum;     /* no effect if defethnum != 0 */
    int defethtype;
    int ethtype;    /* no effect if defethtype != 0 */
};
const struct flags_t DEFAULT_FLAGS = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };

struct kexec_info_t
{
    uint32_t signature;
    uint32_t version;
    uint32_t size;
    uint32_t interactive;
    uint32_t nvram_dump_offset;
    uint32_t boot_disk_pci_addr_node;
    uint32_t boot_disk_pci_addr_bus;
    uint32_t boot_disk_pci_addr_slot;
    uint32_t boot_disk_pci_addr_func;
    uint32_t boot_disk_sata_port;
    uint32_t vga_pci_addr_node;
    uint32_t vga_pci_addr_bus;
    uint32_t vga_pci_addr_slot;
    uint32_t vga_pci_addr_func;
    uint32_t eth_emul_regime;
    uint32_t eth_enabled_num;
    uint32_t reserved[112];     /* total 128 uint32_t's */
} __attribute__((packed));

struct lintelops
{
    char *cache;
    size_t cachesize;
    size_t fptr;

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
    if (l > 0 && arg[l - 1] == '/') arg[l - 1] = '\0';

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

static void parse_pci_id(const char *context, char *pciid, uint32_t *domain, uint32_t *bus, uint32_t *dev, uint32_t *func)
{
    char *s, *endp;
    errno = 0;

    s = strtok(pciid, ":.");
    if (s == NULL) cancel(C_PCI_DOMAIN_NONE, "Can't recognize domain id %s.\n", context);
    *domain = strtol(s, &endp, 16);
    if (errno || *endp) cancel(C_PCI_DOMAIN_WRONG, "Malformed domain id %s.\n", context);

    s = strtok(NULL, ":.");
    if (s == NULL) cancel(C_PCI_BUS_NONE, "Can't recognize bus id %s.\n", context);
    *bus = strtol(s, &endp, 16);
    if (errno || *endp) cancel(C_PCI_BUS_WRONG, "Malformed bus id %s.\n", context);

    s = strtok(NULL, ":.");
    if (s == NULL) cancel(C_PCI_DEV_NONE, "Can't recognize dev id %s.\n", context);
    *dev = strtol(s, &endp, 16);
    if (errno || *endp) cancel(C_PCI_DEV_WRONG, "Malformed dev id %s.\n", context);

    s = strtok(NULL, ":.");
    if (s == NULL) cancel(C_PCI_FUNC_NONE, "Can't recognize func id %s.\n", context);
    *func = strtol(s, &endp, 16);
    if (errno || *endp) cancel(C_PCI_FUNC_WRONG, "Malformed func id %s.\n", context);
}

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

static void reset_devices(const char *bridgeid)
{
    char devpattern[PATH_MAX];
    path_snprintf(devpattern, "PCI bridge subdevice pattern", "/sys/bus/pci/devices/%s/????:??:??.*", bridgeid);
        
    glob_t globbuf;
    switch(glob(devpattern, GLOB_ERR, NULL, &globbuf))
    {
        case 0:
            break;

        case GLOB_NOMATCH:
            globfree(&globbuf);
            cancel(C_BRGLOB_SYSFS, "No bridge subdevices sysfs subdirectory exist; something is completely wrong with your sysfs.\n");

        case GLOB_NOSPACE:
            globfree(&globbuf);
            cancel(C_BRGLOB_ALLOC, "No memory looking for bridge subdevices\n");

        case GLOB_ABORTED:
            globfree(&globbuf);
            cancel(C_BRGLOB_ABORT, "Read error looking for bridge subdevices\n");

        default:
            globfree(&globbuf);
            cancel(C_BRGLOB_UNEXPECTED, "Unexpected error looking for bridge subdevices, internal result: %s\n", strerror(errno));
    }

    for(size_t n = 0; n < globbuf.gl_pathc; ++n)
    {
        char pciremove[PATH_MAX];
        path_snprintf(pciremove, "PCI device removal command pseudofile", "%s/remove", globbuf.gl_pathv[n]);
        printf("Removing PCI device %s.\n", globbuf.gl_pathv[n]);
        write_sysfs(pciremove, "1\n");
    }
}

static void reset_fbdriver(int tty, const struct flags_t flags)
{
    /* Current kernels require specific adapter reset sequence to be performed before kexec. */

    char pcilnk[PATH_MAX];
    char *pciid;

    if(flags.rmmod || flags.rmpci)
    {
        if (tty < 0)
        {
            const char active_file[] = "/sys/class/tty/tty0/active";
            char *active_tty, *endp;
            struct stat st;
            if (stat(active_file, &st) != 0) cancel(C_FBDEV_TTYSTAT, "Can't stat() %s (maybe you don't have tty enabled, try -t <N> if you have): %s\n", active_file, strerror(errno));
            read_sysfs(active_file, &active_tty, NULL);
            errno = 0;
            *strchrnul(active_tty, '\n') = '\0';
            printf("Active tty: %s\n", active_tty);
            if (!active_tty || strlen(active_tty) < 4 || strncmp(active_tty, "tty", 3) || (tty = strtol(&(active_tty[3]), &endp, 10)) <= 0 || errno || *endp)
            {
                free(active_tty);
                cancel(C_FBDEV_TTYWRONG, "Incorrect data in %s, can't autodetect active tty. Use -t <N> to specify it\n", active_file);
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
                cancel(C_FBGLOB_ALLOC, "No memory looking for framebuffers\n");

            case GLOB_ABORTED:
                globfree(&globbuf);
                cancel(C_FBGLOB_ABORT, "Read error looking for framebuffers\n");

            default:
                globfree(&globbuf);
                cancel(C_FBGLOB_UNEXPECTED, "Unexpected error looking for framebuffers, internal result: %s\n", strerror(errno));
        }

        printf("Detecting active framebuffer device for tty%d by %s...\n", tty, globbuf.gl_pathv[0]);
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

    if(flags.vtunbind)
    {
        unbind_vtcon("frame buffer device");
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

    if(flags.rmpci)
    {
        char pciabsdev[PATH_MAX];
        char *pcibridge;
        char pcidev[PATH_MAX];
        path_snprintf(pcidev, "PCI device instance directory", "/sys/bus/pci/devices/%s", pciid);
        path_readlink(pcidev, pciabsdev);
        pcibridge = quick_basename(quick_dirname(pciabsdev));
        printf("Active video device parent PCI bridge is %s.\n", pcibridge);
        reset_devices(pcibridge);
    }
}

static void fill_disk_data(struct kexec_info_t *kexec_info, dev_t dev, int chkdisknode)
{
    char blklink[PATH_MAX];
    char blkabsdev[PATH_MAX];
    path_snprintf(blklink, "Block device sysfs link", "/sys/dev/block/%d:%d", major(dev), minor(dev));
    path_readlink(blklink, blkabsdev);
    char *ataport = strstr(blkabsdev, "/ata");
    if (ataport == NULL) cancel(C_DISKDEV_NONATA, "Device %s is not an ATA device.\n", blklink);
    *ataport++ = '\0';
    *strchrnul(ataport, '/') = '\0';
    char *pcidev = quick_basename(blkabsdev);

    char portfile[PATH_MAX];
    path_snprintf(portfile, "Block device sysfs port number", "/sys/bus/pci/devices/%s/%s/ata_port/%s/port_no", pcidev, ataport, ataport);
    char *portnum, *endp;
    read_sysfs(portfile, &portnum, NULL);
    errno = 0;
    *strchrnul(portnum, '\n') = '\0';
    if ((kexec_info->boot_disk_sata_port = strtol(portnum, &endp, 10)) <= 0 || errno || *endp)
    {
        free(portnum);
        cancel(C_DISKDEV_WRONGPORT, "Incorrect data in %s (%s). Should usually be 1 to 4 (or more on modern controllers)\n", portfile, portnum);
    }
    free(portnum);

    --kexec_info->boot_disk_sata_port;
    parse_pci_id("for the boot drive PCI device", pcidev, &kexec_info->boot_disk_pci_addr_node, &kexec_info->boot_disk_pci_addr_bus, &kexec_info->boot_disk_pci_addr_slot, &kexec_info->boot_disk_pci_addr_func);
    if (chkdisknode && kexec_info->boot_disk_pci_addr_node > 0) cancel(C_DISKDEV_WRONGNODE, "AHCI controller of boot drive should be on CPU 0, not %d.\n", kexec_info->boot_disk_pci_addr_node);
    printf("Requested boot from AHCI controller %04x:%02x:%02x.%x, port %d.\n", kexec_info->boot_disk_pci_addr_node, kexec_info->boot_disk_pci_addr_bus, kexec_info->boot_disk_pci_addr_slot, kexec_info->boot_disk_pci_addr_func, kexec_info->boot_disk_sata_port);
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
    errno = 0;
    while ((ut = getutxent()) != NULL)
    {
        if (ut->ut_type == RUN_LVL)
        {
            runlevel = ut->ut_pid % 256 - '0';
            break;
        }
    }
    endutxent();

    if (runlevel < 0)
    {
        if (errno && errno != ENOENT) cancel(C_RUNLEVEL_FAIL, "Can't get current runlevel: %s\n", strerror(errno));

        char *initstr;
        read_sysfs("/proc/1/cmdline",&initstr,NULL);
        *strchrnul(initstr, ' ') = '\0';
        char *init = quick_basename(initstr);
        /* Feel free to add any other shell you may somehow use as init in your boot config and make a pull request with that change. */
        if (!strcmp(init, "bash") || !strcmp(init, "csh") || !strcmp(init, "sh") || !strcmp(init, "zsh") || !strcmp(init, "rbash") || !strcmp(init, "sh4") || !strcmp(init, "bash4") || !strcmp(init, "rbash4"))
        {
            printf("Init process is a simple shell (%s), assuming we are in runlevel 1.\n", init);
            free(initstr);
            return;
        }
        else
        {
            free(initstr);
            cancel(C_RUNLEVEL_NONE, "Can't get current runlevel: no RUN_LVL entry in utmp file\n");
        }
    }

    if (runlevel != 1) cancel(C_RUNLEVEL_WRONG, "You should run this only from runlevel 1, but current runlevel is %d\n", runlevel);
}

static void free_static(void)
{
    if (lintel.image) free(lintel.image);
    if (kernel.image) free(kernel.image);
    if (kernel.initrd) free(kernel.initrd);
}

static void read_image(struct lintelops *l, FILE *f, size_t realsize, void **out_buf, u64 *out_size, const char *what)
{
    *out_size = realsize; /* Note: this should EXACTLY match the lintel binary size, because it is used to calculate jump address (mcstbug#133402 comment 38) */
    size_t aligned_size = realsize + alignment; aligned_size -= aligned_size % alignment;
    if (posix_memalign(out_buf, alignment, aligned_size)) { l->fclose(f); cancel(C_FILE_ALLOC, "Can't allocate %ld bytes for %s file of %ld bytes\n", aligned_size, what, *out_size); }
    if (l->fread(*out_buf, *out_size, 1, f) != 1) { l->fclose(f); cancel(C_FILE_READ, "Can't read %ld bytes for %s file, file might be truncated\n", *out_size, what); }
    printf("Loaded %s: %ld bytes at address %p (%ld bytes aligned at 0x%lx)\n", what, *out_size, *out_buf, aligned_size, alignment);
    if(l->fclose(f)) cancel(C_FILE_CLOSE, "Can't close %s file\n", what);
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

static void inject_kexec_info(const struct kexec_info_t *source, struct kexec_info_t *target, const char *nvram, struct flags_t *flags)
{
    if (target->signature == 0x61746164)
    {
        switch(target->version)
        {
            case 0x01000000:
                memset(&(((uint32_t*)target)[3]), 0xff, target->size - 3 * sizeof(uint32_t));
                target->interactive             = source->interactive;
                target->boot_disk_pci_addr_node = source->boot_disk_pci_addr_node;
                target->boot_disk_pci_addr_bus  = source->boot_disk_pci_addr_bus;
                target->boot_disk_pci_addr_slot = source->boot_disk_pci_addr_slot;
                target->boot_disk_pci_addr_func = source->boot_disk_pci_addr_func;
                target->boot_disk_sata_port     = source->boot_disk_sata_port;
                target->vga_pci_addr_node       = source->vga_pci_addr_node;
                target->vga_pci_addr_bus        = source->vga_pci_addr_bus;
                target->vga_pci_addr_slot       = source->vga_pci_addr_slot;
                target->vga_pci_addr_func       = source->vga_pci_addr_func;
                target->eth_emul_regime         = source->eth_emul_regime;
                target->eth_enabled_num         = source->eth_enabled_num;

                if(!flags->noinitrd)
                {
                    target->nvram_dump_offset = 6;
                    void *nvbuf = ((char *)target) - (512 * target->nvram_dump_offset);
                    FILE *fn = fopen(nvram, "r");
                    if (fn == NULL) cancel(C_NVRAM_OPEN, "Can't open NVRAM image %s: %s\n", nvram, strerror(errno));
                    size_t fns;
                    if (fseek(fn, 0, SEEK_END) != 0) { fclose(fn); cancel(C_NVRAM_SEEK, "Can't seek NVRAM image: %s\n", strerror(errno)); }
                    if ((fns = ftell(fn)) == -1) { fclose(fn); cancel(C_NVRAM_TELL, "Can't get NVRAM image position: %s\n", strerror(errno)); }
                    rewind(fn);
                    if ((fns <= 0) || (fns > 768)) { fclose(fn); cancel(C_NVRAM_SIZE, "NVRAM image must have size of 1 to 768 bytes.\n"); }
                    printf("Loading NVRAM image from %s (%lu bytes):\n", nvram, fns);
                    if (fread(nvbuf, fns, 1, fn) != 1) { fclose(fn); cancel(C_NVRAM_READ, "Can't read %u bytes of NVRAM image, file might be truncated\n", fns); }
                    printf("Loaded NVRAM image: %lu bytes at address %p (%d sectors before kexec_info at %p)\n", fns, nvbuf, target->nvram_dump_offset, target);
                    if(fclose(fn)) cancel(C_NVRAM_CLOSE, "Can't close NVRAM image\n");
                }
                break;

            default:
                printf("Kexec jumper contains kexec_info structure of unsupported version, so NVRAM image, boot disk, VGA card and trusted mode won't be passed to lintel.\n");
        }
    }
    else printf("Kexec jumper does not contain kexec_info structure, so NVRAM image, boot disk, VGA card and trusted mode won't be passed to lintel.\n");
}

static void load_bcd_lintel(struct lintelops *l, FILE *f, const struct xrt_BcdHeader_t header, const struct kexec_info_t *kexec_info, const char *nvram, struct flags_t *flags)
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
            if ((file.size < 7) && !flags->noinitrd)
            {
                printf("BCD file contain kexec jumper of less than 3584 bytes (7 sectors), no way to fit NVRAM image.\n");
                flags->noinitrd = 1;
            }
            break;
        }
    }
    if (!super_file.size) { l->fclose(f); cancel(C_BCD_NOTFOUND, "Can't find lintel file in BCD file\n"); }

    if (l->fseek(f, 512 * super_file.lba, SEEK_SET) != 0) { l->fclose(f); cancel(C_BCD_SEEK, "Can't seek to start of lintel binary in BCD file: %s\n", strerror(errno)); }
    read_image(l, f, 512 * super_file.size, &lintel.image, &lintel.image_size, "BCD file");
    if (super_file.tag == PRIORITY_TAG_KEXEC_JUMPER)
    {
        patch_jumper_info(super_file);
        inject_kexec_info(kexec_info, (struct kexec_info_t *)(lintel.image + 512 * (super_file.size - 1)), nvram, flags);
    }
    else
    {
        printf("BCD file does not contain kexec jumper, so NVRAM image, boot disk, VGA card and trusted mode won't be passed to lintel.\n");
    }
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
        if(l->cachesize < l->fptr) return 0;
        actual_bytes = l->cachesize - l->fptr;
    }
    if(ptr && actual_bytes) memcpy(ptr, l->cache + l->fptr, actual_bytes);
    l->fptr += actual_bytes;
    return actual_bytes / size;
}

int stdin_fseek(FILE *stream, long offset, int whence)
{
    struct lintelops *l = (struct lintelops*)stream;
    switch(whence)
    {
        case SEEK_SET:
            if (offset < 0) { errno = EINVAL; return -1; }
            l->fptr = offset;
            break;

        case SEEK_CUR:
            if (offset + (long)l->fptr < 0) { errno = EINVAL; return -1; }
            l->fptr += offset;
            break;

        case SEEK_END:
            /* Read by 4k blocks till the end to determine size */
            while (l->fread(NULL, 4096, 1, stream) > 0);
            break;

        default:
            errno = EINVAL; return -1;
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

size_t get_fsize(struct lintelops *l, FILE *f)
{
    size_t r;
    if (l->fseek(f, 0, SEEK_END) != 0) { l->fclose(f); cancel(C_FILE_SEEK, "Can't seek file: %s\n", strerror(errno)); }
    if ((r = l->ftell(f)) == -1) { l->fclose(f); cancel(C_FILE_TELL, "Can't get file position: %s\n", strerror(errno)); }
    l->rewind(f);
    return r;
}

static void load_image(const char *fname, const char *initrd, const char *cmdline, struct flags_t *flags, const struct kexec_info_t *kexec_info)
{
    FILE *f;
    struct lintelops l = { NULL, 0, 0, fread, fseek, ftell, rewind, fclose };
    if(strcmp(fname, "-"))
    {
        /* May be undefined in non-POSIX environments; then we don't expand tilde. */
        #ifndef GLOB_TILDE
            #define GLOB_TILDE 0
        #endif

        printf("Requested image path: %s\n", fname);
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
        if (f == NULL) { globfree(&globbuf); cancel(C_FILE_OPEN_IMAGE, "Can't open image file %s: %s\n", fname, strerror(errno)); }
        printf("Loading image from %s:\n", globbuf.gl_pathv[0]);
        globfree(&globbuf);
    }
    else
    {
        printf("Piping image from standard input\n");
        f = (FILE*)&l;
        l.fread = stdin_fread;
        l.fseek = stdin_fseek;
        l.ftell = stdin_ftell;
        l.rewind = stdin_rewind;
        l.fclose = stdin_fclose;
    }

    struct xrt_BcdHeader_t header = bcd_check_files(&l, f);
    if (header.files_num == -1)
    {
        size_t realsize = get_fsize(&l, f);

        if(flags->iskernel)
        {
            printf ("File seems to be a kernel image.\n");
            read_image(&l, f, realsize, &kernel.image, &kernel.image_size, "kernel");

            if(flags->noinitrd)
            {
                kernel.initrd_size = 0;
            }
            else
            {
                struct lintelops s = { NULL, 0, 0, fread, fseek, ftell, rewind, fclose };
                FILE *fi = fopen(initrd,"r");
                if (fi == NULL) cancel(C_LINUX_OPEN_INITRD, "Can't open initrd file %s: %s\n", initrd, strerror(errno));
                realsize = get_fsize(&s, fi);
                printf("Loading initrd from %s:\n", initrd);
                read_image(&s, fi, realsize, &kernel.initrd, &kernel.initrd_size, "initrd");
            }

            char *oldcmdline = NULL;
            if(flags->cmdline != 'c')
            {
                read_sysfs("/proc/cmdline", &oldcmdline, NULL);
                *strchrnul(oldcmdline, '\n') = '\0';
            }
            if(((flags->cmdline == 'c') ? strlen(cmdline) : (strlen(oldcmdline) + ((flags->cmdline == 1) ? 0 : (strlen(cmdline) + 1)))) >= COMMAND_LINE_SIZE)
            {
                if (oldcmdline) free(oldcmdline);
                cancel(C_LINUX_RESCMDLINE_LONG, "Command line to pass to kernel is longer than %d bytes\n", COMMAND_LINE_SIZE);
            }

            switch(flags->cmdline)
            {
                case 1:
                    strcpy(kernel.cmdline, oldcmdline);
                    break;
                case 'a':
                    strcpy(kernel.cmdline, oldcmdline);
                    strcat(kernel.cmdline, " ");
                    strcat(kernel.cmdline, cmdline);
                    break;
                case 'c':
                    strcpy(kernel.cmdline, cmdline);
                    break;
            }
            kernel.cmdline_size = strlen(kernel.cmdline);
            printf("Kernel command line: %s\n", kernel.cmdline);
        }
        else
        {
            printf ("File seems to be raw lintel image, so NVRAM image, boot disk, VGA card and trusted mode won't be passed.\n");
            read_image(&l, f, realsize, &lintel.image, &lintel.image_size, "lintel");
        }
    }
    else
    {
        flags->iskernel = 0;
        load_bcd_lintel(&l, f, header, kexec_info, initrd, flags);
    }
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

extern const char *vcs_ver;
static void version(const char *argv0)
{
    printf("%s (kexec-e2k) version %s, git revision %s\n", argv0, PROJ_VER, vcs_ver);
    exit(C_SUCCESS);
}

static void usage(const char *argv0, const char *def)
{
    printf("Usage:\n");
    printf("    %s [OPTIONS] [FILE]\n\n", argv0);
    printf("    FILE:             File to start (may be a plain lintel starter or kernel image, lintel BCD image, or a lintel BCD image with kexec jumper)\n");
    printf("                      Wildcards are supported (to prevent shell expansion, put the argument in quotes). Only one file should fit the pattern then.\n");
    printf("                      If not specified, %s is loaded. Use a single dash to load a file from standard input\n", def);
    printf("    OPTIONS:\n");
    printf("        --version:    Show version and exit\n");
    printf("        -h | --help:  Show this help and exit\n");
    printf("        -t | --tty N: Reset framebuffer device associated with ttyN instead of currently active one (has no effect if -b, or both -M and -P are given)\n");
    printf("        -e N:         Allow only N network adapters\n");
    printf("        -E TYPE:      Set network adapter type to TYPE (supported types: `Intel', `PCNet', `Elbrus')\n");
    printf("        -m:           Don't check for unmounted filesystems and don't mount them\n");
    printf("        -i:           Don't check that IOMMU is off\n");
    printf("        -r:           Don't check current runlevel\n");
    printf("        -b:           Don't reset current framebuffer device\n");
    printf("        -f:           Don't sync, flush, and remount-read-only filesystems\n");
    printf("        -V:           Don't unbind currently active vtconsole (has no effect if -b is given)\n");
    printf("        -M:           Don't unload module bound to PCI Express device implementing current framebuffer (has no effect if -b is given)\n");
    printf("        -P:           Don't remove PCI Express device implementing current framebuffer (has no effect if -b is given)\n");
    printf("        -B:           Ignored (for backwards compatibility)\n");
    printf("        -x:           Don't perform actual kexec or kexec_lintel ioctl but everything preceeding it\n");
    printf("When starting kernel image:\n");
    printf("        -I FILE:      Use FILE as initrd image (no initrd image is passed if not specified)\n");
    printf("        -c CMDLINE:   Pass CMDLINE as new kernel command line (one of currently loaded kernel is passed if neither -c nor -a specified)\n");
    printf("        -a CMDLINE:   Add CMDLINE to one of currently loaded kernel to produce new kernel command line\n");
    printf("When starting lintel image:\n");
    printf("        -l:           Treat non-BCD file as a lintel starter, not kernel image\n");
    printf("        -d DEVNAME:   Avoid asking for boot drive and boot guest OS from DEVNAME (e.g. /dev/sdc) by default\n");
    printf("        -N FILE:      Use FILE as NVRAM image (if not specified, lintel will read actual NVRAM). Create it by calling dd if=/dev/nvram of=FILE bs=256 skip=1 count=3\n");
    printf("        -T:           Prohibit lintel to react at any keypress to perform a controlled trusted boot (has an effect only if -d is given)\n");
    printf("        -n:           Don't check that boot disk AHCI controller is on node 0 (has an effect only if -d is given)\n");
    printf("        -v:           Don't pass current video adapter id to lintel and make it load on the one it has in NVRAM\n");
    exit(C_SUCCESS);
}

static const char *check_args(int argc, char * const argv[], const char *def, int *tty, struct flags_t *flags, dev_t *disk, char cmdline[], char initrd[])
{
    int is_nvram = 0;
    for(;;)
    {
        int opt = getopt(argc, argv, "h-:t:d:I:N:c:a:e:E:TnmlirbfvVMPBx");
        if(opt == -1)
        {
            return (optind >= argc) ? def : argv[optind];
        }

        char *endp;
        switch(opt)
        {
            case 'T':
                flags->untrusted = 0;
                break;

            case 'n':
                flags->chkdisknode = 0;
                break;

            case 'm':
                flags->mounts = 0;
                break;

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

            case 'v':
                flags->setvideo = 0;
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
                break;

            case 'x':
                flags->kexec = 0;
                break;

            case 'l':
                flags->iskernel = 0;
                break;

            case 'e':
                flags->defethnum = 0;
                errno = 0;
                flags->ethnum = strtol(optarg, &endp, 0);
                if (errno || *endp || flags->ethnum < 0)
                {
                    cancel(C_OPTARG_WRONG_ETHNUM, "%s: %s is not a correct network adapter count\nRun %s --help for usage)\n", argv[0], optarg, argv[0]);
                }
                break;

            case 'E':
                flags->defethtype = 0;
                if      (!strcmp(optarg, "Intel"))  flags->ethtype = 0;
                else if (!strcmp(optarg, "PCNet"))  flags->ethtype = 1;
                else if (!strcmp(optarg, "Elbrus")) flags->ethtype = 2;
                else
                {
                    cancel(C_OPTARG_WRONG_ETHTYPE, "%s: type `%s' is not one of allowed types: `Intel', `PCNet', `Elbrus'\nRun %s --help for usage)\n", argv[0], optarg, argv[0]);
                }
                break;

            case 'd':
                flags->askfordisk = 0;
                struct stat st;
                if (stat(optarg, &st))
                {
                    cancel(C_OPTARG_WRONG_DISK, "%s: can't stat device %s\nRun %s --help for usage)\n", argv[0], optarg, argv[0]);
                }
                *disk = st.st_rdev;
                break;

            case 'c':
            case 'a':
                flags->cmdline = opt;
                if(strlen(optarg) >= COMMAND_LINE_SIZE) cancel(C_LINUX_CMDLINE_LONG, "%s: passed command line is longer than %d bytes\n", argv[0], COMMAND_LINE_SIZE);
                strcpy(cmdline, optarg);
                break;

            case 'N':
                is_nvram = 1;
            case 'I':
                flags->noinitrd = 0;
                if(strlen(optarg) >= PATH_MAX) cancel(C_LINUX_INITRD_LONG, "%s: passed %s path is longer than %d bytes\n", argv[0], (is_nvram ? "NVRAM" : "initrd"), PATH_MAX);
                strcpy(initrd, optarg);
                break;

            case '?':
                cancel(C_OPTARG, "Run %s --help for usage\n", argv[0]);

            case 'h':
                usage(argv[0], def);

            case '-':
                if(!strcmp(optarg, "help")) usage(argv[0], def);
                if(!strcmp(optarg, "version")) version(argv[0]);
                if(strcmp(optarg, "tty")) cancel(C_OPTARG_LONG, "%s: incorrect long option -- '%s'\nRun %s --help for usage\n", argv[0], optarg, argv[0]);
                if(optind >= argc) cancel(C_OPTARG, "%s: option requires an argument -- '--tty'\nRun %s --help for usage\n", argv[0], argv[0]);
                optarg = argv[optind++];

            case 't':
                errno = 0;
                *tty = strtol(optarg, &endp, 0);
                if (errno || *endp || *tty < 0)
                {
                    cancel(C_OPTARG_WRONG_TTY, "%s: malformed tty number %s\nRun %s --help for usage)\n", argv[0], optarg, argv[0]);
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

static int get_dev(const char *path)
{
    struct stat st;
    if(stat(path, &st) == -1) cancel(C_MOUNTS_STAT, "Can't stat mountpoint %s: %s\n", path, strerror(errno));
    return st.st_dev;
}

static void try_mount(const char *src, const char *tgt)
{
    printf("Filesystem %s (%s) is not mounted, trying to fix it...\n", tgt, src);
    if (mount(src, tgt, src, 0, NULL) != 0) cancel(C_MOUNTS_MOUNT, "Can't mount %s: %s\n", tgt, strerror(errno));
}

static void check_mountpoints()
{
    int dev_root = get_dev("/");
    int dev_dev  = get_dev("/dev");
    int dev_sys  = get_dev("/sys");
    int dev_proc = get_dev("/proc");
    if (dev_root == dev_dev)  try_mount("devtmpfs", "/dev");
    if (dev_root == dev_sys)  try_mount("sysfs", "/sys");
    if (dev_root == dev_proc) try_mount("proc", "/proc");
}

int main(int argc, char *argv[])
{
    int tty = -1;
    struct flags_t flags = DEFAULT_FLAGS;
    struct kexec_info_t kexec_info;
    dev_t disk;
    memset(&kexec_info, 0xff, sizeof(kexec_info));
    char cmdline[COMMAND_LINE_SIZE];
    char initrd[PATH_MAX];
    memset(cmdline, 0, COMMAND_LINE_SIZE);
    memset(initrd, 0, PATH_MAX);
    const char *fname = check_args(argc, argv, "/opt/mcst/lintel/bin/lintel_*.disk", &tty, &flags, &disk, cmdline, initrd);
    lintel.image = NULL;
    kernel.cmdline = kcmdline;
    kernel.cmdline_size = 0;
    kernel.image = NULL;
    kernel.initrd = NULL;
    memset(kcmdline, 0, COMMAND_LINE_SIZE);
    atexit(free_static);

    if (flags.mounts)
    {
        check_mountpoints();
    }

    if (flags.iommu)
    {
        check_iommu();
    }

    if (flags.runlevel)
    {
        check_runlevel();
    }

    if (flags.defethtype)
    {
        kexec_info.eth_emul_regime = flags.ethtype;
    }

    if (flags.defethnum)
    {
        kexec_info.eth_enabled_num = flags.ethnum;
    }

    if (flags.setvideo)
    {
        char *vgaarb;
        read_sysfs("/dev/vga_arbiter", &vgaarb, NULL);
        if(!strncmp(vgaarb, "invalid", 7))
        {
            printf("VGA arbiter has no idea of which video card is active, lintel will boot on the last saved one.\n");
        }
        else
        {
            char *pcidev = strstr(vgaarb, "PCI:");
            if (pcidev == NULL) { free(vgaarb); cancel(C_VGA_PCI, "Can't find PCI device signature in VGA arbiter response\n"); }
            pcidev += 4;
            *strchrnul(pcidev, ',') = '\0';
            parse_pci_id("of current VGA card", pcidev, &kexec_info.vga_pci_addr_node, &kexec_info.vga_pci_addr_bus, &kexec_info.vga_pci_addr_slot, &kexec_info.vga_pci_addr_func);
            printf("Active VGA card to boot lintel on is %04x:%02x:%02x.%x.\n", kexec_info.vga_pci_addr_node, kexec_info.vga_pci_addr_bus, kexec_info.vga_pci_addr_slot, kexec_info.vga_pci_addr_func);
        }
        free(vgaarb);
    }

    if (!flags.askfordisk)
    {
        fill_disk_data(&kexec_info, disk, flags.chkdisknode);
        if (!flags.untrusted)
        {
            kexec_info.interactive = 0;
        }
    }

    load_image(fname, initrd, cmdline, &flags, &kexec_info);

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

    if (!flags.kexec)
    {
        return 0;
    }

    printf("Rebooting to image...\n");
    int kexec_fd = open_kexec();
    int rv = ioctl(kexec_fd, (flags.iskernel ? KEXEC_REBOOT : LINTEL_REBOOT), (flags.iskernel ? (void*)&kernel : (void*)&lintel));
    int err = errno;
    close(kexec_fd);
    cancel(C_DEV_IOCTL, "Failure performing ioctl (returned %d) to start image: %s\n", rv, strerror(err));

    if (flags.fsflush)
    {
        printf("Note: you should at least remount everything back to rw to bring system back to work\n");
    }
}
#endif
