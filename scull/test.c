#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <linux/ioctl.h>

#define SCULL_IOC_MAGIC 'k'
#define SCULL_IOC_RESET _IO(SCULL_IOC_MAGIC, 0)
#define SCULL_IOCS_QUANTUM _IOW(SCULL_IOC_MAGIC, 1, int)
#define SCULL_IOCS_QSET _IOW(SCULL_IOC_MAGIC, 2, int)
#define SCULL_IOCT_QUANTUM _IO(SCULL_IOC_MAGIC, 3)
#define SCULL_IOCT_QSET _IO(SCULL_IOC_MAGIC, 4)
#define SCULL_IOCG_QUANTUM _IOR(SCULL_IOC_MAGIC, 5, int)
#define SCULL_IOCG_QSET _IOR(SCULL_IOC_MAGIC, 6, int)
#define SCULL_IOCQ_QUANTUM _IO(SCULL_IOC_MAGIC, 7)
#define SCULL_IOCQ_QSET _IO(SCULL_IOC_MAGIC, 8)
#define SCULL_IOCX_QUANTUM _IOWR(SCULL_IOC_MAGIC, 9, int)
#define SCULL_IOCX_QSET _IOWR(SCULL_IOC_MAGIC, 10, int)
#define SCULL_IOCH_QUANTUM _IO(SCULL_IOC_MAGIC, 11)
#define SCULL_IOCH_QSET _IO(SCULL_IOC_MAGIC, 12)
#define SCULL_IOC_MAXNR 13



int main(int argc, char **argv) {
    int quantum = 5000;
    int qset = 2000;
#if 0
    int fd = open("scull0", O_RDONLY);
    printf("quantum is %d , qset is %d \n", ioctl(fd, SCULL_IOCQ_QUANTUM), ioctl(fd, SCULL_IOCQ_QSET));
    printf("set quantum %d, set qset %d\n", ioctl(fd, SCULL_IOCT_QUANTUM, quantum), ioctl(fd, SCULL_IOCT_QSET, qset));

    printf("get quantum %d, get qset %d\n", ioctl(fd, SCULL_IOCG_QUANTUM, &quantum), ioctl(fd, SCULL_IOCG_QSET, &qset));
    printf("quantum %d, qset %d\n", quantum, qset);
    printf("set quantum %d, set qset %d\n", ioctl(fd, SCULL_IOCS_QUANTUM, &quantum), ioctl(fd, SCULL_IOCS_QSET, &qset));

    quantum = 6000;
    qset = 3000;
    printf("exchange quantum %d, exchange qset %d\n", ioctl(fd, SCULL_IOCX_QUANTUM, &quantum), ioctl(fd, SCULL_IOCX_QSET, &qset));
    printf("quantum %d, qset %d\n", quantum, qset);
    printf("shift quantum %d, shift qset %d\n", ioctl(fd, SCULL_IOCH_QUANTUM, 4000), ioctl(fd, SCULL_IOCH_QSET, 1000));
    close(fd);
#endif

    int fd = open(argv[1], O_RDONLY);
    while(1);
    return 0;
}
