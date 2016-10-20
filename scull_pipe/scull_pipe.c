#include <linux/module.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <linux/kernel.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/semaphore.h>
#include <linux/moduleparam.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/poll.h>

#include "scull_pipe.h"

MODULE_LICENSE("Dual BSD/GPL");

static struct scull_pipe scull_p_dev;
static dev_t scull_p_devno;

static int buffer_size = DEFAULT_BUFFER_SIZE;
static int max_rds = DEFAULT_RDS;
static int max_wrs = DEFAULT_WRS;
module_param(buffer_size, int, S_IRUGO);
module_param(max_rds, int, S_IRUGO);
module_param(max_wrs, int, S_IRUGO);

static struct file_operations scull_p_fops = {
    .owner = THIS_MODULE,
    .open = scull_p_open,
    .release = scull_p_release,
    .read = scull_p_read,
    .write = scull_p_write,
    .poll = scull_p_poll,
    .fasync = scull_p_fasync,
};

static int init_scull_p_dev(struct scull_pipe *dev, int buf_sz){
    dev->buffer = (char*)kmalloc(buf_sz, GFP_KERNEL);
    dev->buffer_size = buf_sz;
    if(!dev->buffer)
        return -ENOMEM;
    sema_init(&dev->sem, 1);
    sema_init(&dev->open_sem, 1);
    init_waitqueue_head(&dev->rd_q);
    init_waitqueue_head(&dev->wr_q);
    init_waitqueue_head(&dev->op_q);
    dev->rd_pos = 0;
    dev->wr_pos = 0;
    dev->nr_rds = 0;
    dev->nr_wrs = 0;
    dev->async_q = NULL;
    return 0;
}

static int __init scull_p_init(void){
    int ret;
    ret = alloc_chrdev_region(&scull_p_devno, 0, 1, "scullpipe");
    if(ret < 0)
        return ret;
    ret = init_scull_p_dev(&scull_p_dev, buffer_size);
    if(ret < 0){
        unregister_chrdev_region(scull_p_devno, 1);
        return ret;
    }
    cdev_init(&scull_p_dev.cdev, &scull_p_fops);
    scull_p_dev.cdev.owner = THIS_MODULE;
    scull_p_dev.cdev.ops = &scull_p_fops;
    ret = cdev_add(&scull_p_dev.cdev, scull_p_devno, 1);
    if(ret){
        kfree(scull_p_dev.buffer);
        unregister_chrdev_region(scull_p_devno, 1);
        return ret;
    }
    return 0;
}


static void __exit scull_p_exit(void){
    cdev_del(&scull_p_dev.cdev);
    kfree(scull_p_dev.buffer);
    unregister_chrdev_region(scull_p_devno, 1);
}


module_init(scull_p_init);
module_exit(scull_p_exit);


int scull_p_open(struct inode *inode, struct file *filp){
    struct scull_pipe *dev = container_of(inode->i_cdev, struct scull_pipe, cdev);
    int is_rd = 0, is_wr = 0;
    switch(filp->f_flags & O_ACCMODE){
        case O_RDONLY: is_rd = 1; is_wr = 0; break;
        case O_WRONLY: is_rd = 0; is_wr = 1; break;
        case O_RDWR: is_rd = 1; is_wr = 1; break;
        default: printk(KERN_WARNING "%s(%d) open mode invalid!\n", current->comm, current->pid); return -EFAULT;
    }
    if(down_interruptible(&dev->open_sem))
        return -ERESTARTSYS;
    while((is_rd && dev->nr_rds == max_rds) || (is_wr && dev->nr_wrs == max_wrs)){
        up(&dev->open_sem);
        if(filp->f_flags & O_NONBLOCK)
            return -EAGAIN;
        SCULL_P_DEBUG("OPEN-LIMITTED! process %s(%d) going to sleep!\n", current->comm, current->pid);
        if(wait_event_interruptible(dev->op_q, !((is_rd && dev->nr_rds == max_rds) || (is_wr && dev->nr_wrs == max_wrs))))
            return -ERESTARTSYS;
        if(down_interruptible(&dev->open_sem))
            return -ERESTARTSYS;
    }
    dev->nr_rds += is_rd;
    dev->nr_wrs += is_wr;
    filp->private_data = (void*)dev;
    up(&dev->open_sem);
    SCULL_P_DEBUG("process %s(%d) open pipe success!\n", current->comm, current->pid);
    return 0;
}

int scull_p_release(struct inode *inode, struct file *filp){
    struct scull_pipe *dev = container_of(inode->i_cdev, struct scull_pipe, cdev);
    int is_rd = 0, is_wr = 0;
    switch(filp->f_flags & O_ACCMODE){
        case O_RDONLY: is_rd = 1; is_wr = 0; break;
        case O_WRONLY: is_rd = 0; is_wr = 1; break;
        case O_RDWR: is_rd = 1; is_wr = 1; break;
    }
    if(down_interruptible(&dev->open_sem))
        return -ERESTARTSYS;
    dev->nr_rds -= is_rd;
    dev->nr_wrs -= is_wr;
    scull_p_fasync(-1, filp, 0);
    up(&dev->open_sem);
    wake_up_interruptible(&dev->op_q);
    return 0;
}

ssize_t scull_p_read(struct file *filp, char __user *buf, size_t count, loff_t *fpos){
    struct scull_pipe *dev = (struct scull_pipe*)filp->private_data;
    if(down_interruptible(&dev->sem))
        return -ERESTARTSYS;
    while(dev->rd_pos == dev->wr_pos){
        up(&dev->sem);
        if(filp->f_flags & O_NONBLOCK)
            return -EAGAIN;
        SCULL_P_DEBUG("NODATA! process %s(%d) going to sleep!\n", current->comm, current->pid);
        if(wait_event_interruptible(dev->rd_q, dev->rd_pos != dev->wr_pos))
            return -ERESTARTSYS;
        if(down_interruptible(&dev->sem))
            return -ERESTARTSYS;
    }
    SCULL_P_DEBUG("process %s(%d) want to read %d bytes from pipe([rd]%d,[wr]%d)!\n", current->comm, current->pid, (int)count, dev->rd_pos, dev->wr_pos);
    if(dev->wr_pos > dev->rd_pos){
        count = SCULL_MIN(count, dev->wr_pos - dev->rd_pos);
        if(copy_to_user(buf, dev->buffer + dev->rd_pos, count)){
            up(&dev->sem);
            return -EFAULT;
        }
        dev->rd_pos += count;
    }else{
        count = SCULL_MIN(count, dev->wr_pos + dev->buffer_size - dev->rd_pos);
        if(dev->rd_pos + count <= dev->buffer_size){
            if(copy_to_user(buf, dev->buffer + dev->rd_pos, count)){
                up(&dev->sem);
                return -EFAULT;
            }
        }else{
            int first_part = dev->buffer_size - dev->rd_pos;
            if(copy_to_user(buf, dev->buffer + dev->rd_pos, first_part)){
                up(&dev->sem);
                return -EFAULT;
            }
            if(copy_to_user(buf + first_part, dev->buffer, count - first_part)){
                up(&dev->sem);
                return -EFAULT;
            }
        }
        dev->rd_pos = (dev->rd_pos + count) % dev->buffer_size;
    }
    up(&dev->sem);
    wake_up_interruptible(&dev->wr_q);
    SCULL_P_DEBUG("process %s(%d) read %d bytes, new pipe([rd]%d, [wr]%d)!\n", current->comm, current->pid, (int)count, dev->rd_pos, dev->wr_pos);
    return count;
}

ssize_t scull_p_write(struct file *filp, const char __user *buf, size_t count, loff_t *fpos){
    struct scull_pipe *dev = (struct scull_pipe*)filp->private_data;
    if(down_interruptible(&dev->sem))
        return -ERESTARTSYS;
    while((dev->wr_pos + 1) % dev->buffer_size == dev->rd_pos){
        up(&dev->sem);
        if(filp->f_flags & O_NONBLOCK)
            return -EAGAIN;
        SCULL_P_DEBUG("NOSPACE! process %s(%d) going to sleep!\n", current->comm, current->pid);
        if(wait_event_interruptible(dev->wr_q, (dev->wr_pos + 1) % dev->buffer_size != dev->rd_pos))
            return -ERESTARTSYS;
        if(down_interruptible(&dev->sem))
            return -ERESTARTSYS;
    }
    SCULL_P_DEBUG("process %s(%d) want to write %d bytes to pipe([rd]%d,[wr]%d)!\n", current->comm, current->pid, (int)count, dev->rd_pos, dev->wr_pos);
    if(dev->wr_pos < dev->rd_pos){
        count = SCULL_MIN(count, dev->rd_pos - dev->wr_pos - 1);
        if(copy_from_user(dev->buffer + dev->wr_pos, buf, count)){
            up(&dev->sem);
            return -EFAULT;
        }
        dev->wr_pos += count;
    }else{
        count = SCULL_MIN(count, dev->buffer_size - dev->wr_pos + dev->rd_pos - 1);
        if(dev->wr_pos + count <= dev->buffer_size){
            if(copy_from_user(dev->buffer + dev->wr_pos, buf, count)){
                up(&dev->sem);
                return -EFAULT;
            }
        }else{
            int first_part = dev->buffer_size - dev->wr_pos;
            if(copy_from_user(dev->buffer + dev->wr_pos, buf, first_part)){
                up(&dev->sem);
                return -EFAULT;
            }
            if(copy_from_user(dev->buffer, buf + first_part, count - first_part)){
                up(&dev->sem);
                return -EFAULT;
            }
        }
        dev->wr_pos = (dev->wr_pos + count) % dev->buffer_size;
    }
    if(dev->async_q)
        kill_fasync(&dev->async_q, SIGIO, POLL_IN);
    up(&dev->sem);
    wake_up_interruptible(&dev->rd_q);
    SCULL_P_DEBUG("process %s(%d) write %d bytes, new pipe([rd]%d,[wr]%d)!\n", current->comm, current->pid, (int)count, dev->rd_pos, dev->wr_pos);
    return count;
}

unsigned int scull_p_poll(struct file *filp, poll_table *wait){
    struct scull_pipe *dev = (struct scull_pipe*)filp->private_data;
    unsigned int mask = 0;
    if(down_interruptible(&dev->sem))
        return -ERESTARTSYS;
    poll_wait(filp, &dev->rd_q, wait);
    poll_wait(filp, &dev->wr_q, wait);
    if(dev->rd_pos != dev->wr_pos)
        mask |= POLLIN | POLLRDNORM;
    if((dev->wr_pos + 1) % dev->buffer_size != dev->rd_pos)
        mask |= POLLOUT | POLLWRNORM;
    up(&dev->sem);
    SCULL_P_DEBUG("process %s(%d) called poll!\n", current->comm, current->pid);
    return mask;
}

int scull_p_fasync(int fd, struct file *filp, int mode){
    struct scull_pipe *dev = (struct scull_pipe*)filp->private_data;
    return fasync_helper(fd, filp, mode, &dev->async_q);
}
