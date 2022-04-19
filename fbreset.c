#include "common.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/fb.h>
#include <pci/pci.h>

static int con2fbmap(int tty)
{
    /* See con2fbmap by Michael J. Hammel: https://gitlab.com/pibox/con2fbmap */
    const char *fbpath = "/dev/fb0";  /* any frame buffer will do */

    int fd;
    struct fb_con2fbmap map;
    map.console = tty;

    if ((fd = open(fbpath, O_RDONLY)) == -1)
    {
        if (errno == ENOENT) return -1;
        cancel(C_FBDEV_OPEN, "Can't open framebuffer device %s: %s\n", fbpath, strerror(errno));
    }
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

    #ifndef NO_BRIDGE_RESET
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
    #else
        printf("Compiled without libpci, won't reset the bridge (%04d:%02d:%02d.%02d).\n", domain, bus, dev, func);
    #endif
}

static void delete_module(const char *name)
{
    if (syscall(SYS_delete_module, name, O_NONBLOCK) == -1) cancel(C_RMMOD_FAULT, "Can't remove module %s: %s\n", name, strerror(errno));
}

static int detect_vtcon(const char *signature)
{
    DIR *pdir;
    struct dirent *pdirent;
    char *contents;

    if ((pdir = opendir("/sys/devices/virtual/vtconsole/")) == NULL) cancel(C_VTCON_OPENDIR, "Can't open vtconsole directory: %s\n", strerror(errno));

    for(;;)
    {
        errno = 0;
        pdirent = readdir(pdir);
        if (pdirent == NULL)
        {
            int e = errno;
            closedir(pdir);
            if (e) cancel(C_VTCON_READDIR, "Can't read vtconsole directory: %s\n", strerror(errno));
            cancel(C_VTCON_NOTFOUND, "Can't find console that is %s.\n", signature);
        }

        if (pdirent->d_name[0] == '.') continue;
        char name[PATH_MAX];
        if(path_snprintf_nc(name, "/sys/class/vtconsole/%s/name", pdirent->d_name) == -1)
        {
            closedir(pdir);
            cancel(C_VTCON_PATHLONG, "Path to virtual console name is greater than %d bytes", name, PATH_MAX - 1);
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
        cancel(C_VTCON_WRONGNAME, "Virtual console name %s is wrong", desired);
    }

    char *endp;
    errno = 0;
    int vtconnum = strtol(desired + 5, &endp, 10);
    if (errno || *endp)
    {
        closedir(pdir);
        cancel(C_VTCON_WRONGNUM, "Malformed vtcon number in sysfs.\n");
    }

    if(closedir(pdir)) cancel(C_VTCON_CLOSEDIR, "Can't close vtconsole directory: %s\n", strerror(errno));
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
