#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/wait.h>
#include <linux/semaphore.h>
#include <linux/cdev.h>
#include <linux/kdev_t.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/kernel.h>

MODULE_LICENSE("Dual BSD/GPL");


ssize_t sleepy_read(struct file *filp, char __user *buf, size_t count, loff_t *fpos);
ssize_t sleepy_write(struct file *filp, const char __user *buf, size_t count, loff_t *fpos);

static DEFINE_SEMAPHORE(sleepy_sem);
static int counter = 0;
static DECLARE_WAIT_QUEUE_HEAD(wq);
static dev_t devno;
static struct cdev sleepy_dev;
static struct file_operations sleepy_fops = {
    .owner = THIS_MODULE,
    .read = sleepy_read,
    .write = sleepy_write,
};

ssize_t sleepy_read(struct file *filp, char __user *buf, size_t count, loff_t *fpos) {
    printk(KERN_DEBUG "process %d (%s) going to sleep!\n", current->pid, current->comm);
REWAIT:
    wait_event_interruptible(wq, counter != 0);
    down(&sleepy_sem);
    if(!counter) {
        up(&sleepy_sem);
        goto REWAIT;
    }
    counter--;
    up(&sleepy_sem);
    printk(KERN_DEBUG "process %d (%s) wake up!\n", current->pid, current->comm);
    return 0;
}

ssize_t sleepy_write(struct file *filp, const char __user *buf, size_t count, loff_t *fpos) {
    printk(KERN_DEBUG "process %d (%s) going to wake up others!\n", current->pid, current->comm);
    down(&sleepy_sem);
    counter++;
    up(&sleepy_sem);
    wake_up_interruptible(&wq);
    return count;
}

static int __init sleepy_init(void) {
    int ret;
    ret = alloc_chrdev_region(&devno, 0, 1, "sleepy");
    if(ret)
        return ret;
    cdev_init(&sleepy_dev, &sleepy_fops);
    sleepy_dev.owner = THIS_MODULE;
    sleepy_dev.ops = &sleepy_fops;
    ret = cdev_add(&sleepy_dev, devno, 1);
    if(ret) {
        unregister_chrdev_region(devno, 1);
        return ret;
    }
    return 0;   
}

static void __exit sleepy_exit(void) {
    cdev_del(&sleepy_dev);
    unregister_chrdev_region(devno, 1);
}

module_init(sleepy_init);
module_exit(sleepy_exit);
