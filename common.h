#ifndef KEXEC_LINTEL_COMMON_H
#define KEXEC_LINTEL_COMMON_H

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
    C_SYSRQ_OPEN = 50,
    C_SYSRQ_WRITE,
    C_SYSRQ_CLOSE,
    C_IOMMU_ENABLED = 55,
    C_IOMMU_STAT,
    C_FBDEV_OPEN = 60,
    C_FBDEV_IOCTL,
    C_FBDEV_CLOSE,
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
    C_VTCON_NOTFOUND,
    C_VTCON_PATHLONG,
    C_VTCON_WRONGNAME,
    C_VTCON_WRONGNUM,
    C_VTCON_CLOSEDIR
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

void cancel(int num, const char *fmt, ...);
void check_iommu(void);
void reset_fbdriver(int tty, const struct flags_t flags);

#endif
