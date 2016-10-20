#ifndef SCULL_H
#define SCULL_H

#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/semaphore.h>
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

struct scull_qset {
    void **data;
    struct scull_qset *next;
};

struct scull_dev {
    struct cdev cdev;
    struct scull_qset *data;
    int quantum;
    int qset;
    int size;
    struct semaphore sem;
};

int scull_open(struct inode *inode, struct file *filp);
int scull_release(struct inode *inode, struct file *filp);
ssize_t scull_read(struct file *filp, char __user *buf, size_t count, loff_t *fpos);
ssize_t scull_write(struct file *filp, const char __user *buf, size_t count, loff_t *fpos);
loff_t scull_llseek(struct file *filp, loff_t off, int whence);
long scull_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);

int scull_s_open(struct inode *inode, struct file *filp);
int scull_s_release(struct inode *inode, struct file *filp);

int scull_u_open(struct inode *inode, struct file *filp);
int scull_u_release(struct inode *inode, struct file *filp);

int scull_w_open(struct inode *inode, struct file *filp);
int scull_w_release(struct inode *inode, struct file *filp);

struct scull_list_item{
    struct scull_dev dev;
    dev_t key;
    struct list_head list;
};
int scull_priv_open(struct inode *inode, struct file *filp);
int scull_priv_release(struct inode *inode, struct file *filp);
#endif
