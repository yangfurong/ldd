#ifndef _SCULL_PIPE_H_
#define _SCULL_PIPE_H_

#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/semaphore.h>
#include <linux/kernel.h>
#include <linux/poll.h>

#define DEFAULT_BUFFER_SIZE 1000
#define DEFAULT_RDS 3
#define DEFAULT_WRS 3

#ifndef SCULL_P_RELEASE
#define SCULL_P_DEBUG(fmt, args...) printk(KERN_DEBUG "scullpipe: " fmt, ##args)
#else
#define SCULL_P_DEBUG(fmt, args...)
#endif

#define SCULL_MIN(a, b) (a) < (b) ? (a) : (b)

struct scull_pipe{
    char *buffer;
    int rd_pos;
    int wr_pos;
    int buffer_size;
    struct semaphore sem;
    wait_queue_head_t rd_q;
    wait_queue_head_t wr_q;
    wait_queue_head_t op_q;
    struct cdev cdev;
    int nr_rds;
    int nr_wrs;
    struct semaphore open_sem;
    struct fasync_struct *async_q;
};

int scull_p_open(struct inode *inode, struct file *filp);
int scull_p_release(struct inode *inode, struct file *filp);
ssize_t scull_p_read(struct file *filp, char __user *buf, size_t count, loff_t *fpos);
ssize_t scull_p_write(struct file *filp, const char __user *buf, size_t count, loff_t *fpos);
unsigned int scull_p_poll(struct file *filp, poll_table *wait);
int scull_p_fasync(int fd, struct file *filp, int mode);

#endif
