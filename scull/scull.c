#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/cdev.h>
#include <linux/moduleparam.h>
#include <linux/errno.h>
#include <linux/semaphore.h>
#include <linux/ioctl.h>
#include <linux/rwsem.h>
#include <linux/capability.h>
#include <asm/atomic.h>
#include <linux/spinlock.h>
#include <linux/spinlock_types.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/tty.h>
#include <asm/hardirq.h>
#include "scull.h"

#define DEVICE_NUM 8
#define DEFAULT_QUANTUM 4000
#define DEFAULT_QSET 1000
#define DEFAULT_MAJOR 0
#define DEFAULT_MINOR 0
#define SCULL_MIN(a, b) ((a) < (b) ? (a) : (b))
#define SCULL_MAX_NORM_DEVNO 3
#define SCULL_S_DEVNO 4
#define SCULL_U_DEVNO 5
#define SCULL_W_DEVNO 6
#define SCULL_PRIV_DEVNO 7

MODULE_LICENSE("Dual BSD/GPL");

static struct scull_dev scull_devs[DEVICE_NUM];
static struct file_operations scull_fops = {
    .owner = THIS_MODULE,
    .open = scull_open,
    .release = scull_release,
    .read = scull_read,
    .write = scull_write,
    .llseek = scull_llseek,
    .unlocked_ioctl = scull_ioctl,
};

static atomic_t scull_s_counter = ATOMIC_INIT(1);
static struct file_operations scull_s_fops = {
    .owner = THIS_MODULE,
    .open = scull_s_open,
    .release = scull_s_release,
    .read = scull_read,
    .write = scull_write,
    .llseek = scull_llseek,
    .unlocked_ioctl = scull_ioctl,
};

static DEFINE_SPINLOCK(scull_u_lock);
static unsigned int scull_u_owner = 0;
static unsigned int scull_u_counter = 0;
static struct file_operations scull_u_fops = {
    .owner = THIS_MODULE,
    .open = scull_u_open,
    .release = scull_u_release,
    .read = scull_read,
    .write = scull_write,
    .llseek = scull_llseek,
    .unlocked_ioctl = scull_ioctl,
};

static DEFINE_SPINLOCK(scull_w_lock);
static unsigned int scull_w_owner = 0;
static unsigned int scull_w_counter = 0;
static DECLARE_WAIT_QUEUE_HEAD(scull_w_wq);
static struct file_operations scull_w_fops = {
    .owner = THIS_MODULE,
    .open = scull_w_open,
    .release = scull_w_release,
    .read = scull_read,
    .write = scull_write,
    .llseek = scull_llseek,
    .unlocked_ioctl = scull_ioctl,
};

static LIST_HEAD(scull_priv_list);
static DEFINE_SPINLOCK(scull_priv_lock);
static struct file_operations scull_priv_fops = {
    .owner = THIS_MODULE,
    .open = scull_priv_open,
    .release = scull_priv_release,
    .read = scull_read,
    .write = scull_write,
    .llseek = scull_llseek,
    .unlocked_ioctl = scull_ioctl,
};

static struct semaphore scull_sem;
static int scull_quantum = DEFAULT_QUANTUM;
static int scull_qset = DEFAULT_QSET;
static int scull_major = DEFAULT_MAJOR;
static int scull_minor = DEFAULT_MINOR;
module_param(scull_quantum, int, S_IRUGO);
module_param(scull_qset, int, S_IRUGO);
module_param(scull_major, int, S_IRUGO);
module_param(scull_minor, int, S_IRUGO);

static void scull_trim(struct scull_dev *dev) {
    struct scull_qset *dptr, *head;
    int qset = dev->qset;
    int quantum_index;
    for(dptr = dev->data; dptr;) {
        if(dptr) {
            if(dptr->data) {
                for(quantum_index = 0; quantum_index < qset; quantum_index++) {
                    if(dptr->data[quantum_index]) {
                        printk(KERN_ALERT "kfree: quantum index %d\n", quantum_index);
                        kfree(dptr->data[quantum_index]);
                    }
                }
                printk(KERN_ALERT "kfree: dptr->data\n");
                kfree(dptr->data);
            }
            head = dptr;
            dptr = dptr->next;
            printk(KERN_ALERT "kfree: head\n");
            kfree(head);
        }
    }
    dev->data = NULL;
    dev->size = 0;
    dev->quantum = scull_quantum;
    dev->qset = scull_qset;
}

int scull_open(struct inode *inode, struct file *filp) {
    struct scull_dev *dev;
    dev = container_of(inode->i_cdev, struct scull_dev, cdev);
    filp->private_data = (void*)dev;
    if((filp->f_flags & O_ACCMODE) == O_WRONLY) {
        if(down_interruptible(&dev->sem))
            return -ERESTARTSYS;
        scull_trim(dev);
        up(&dev->sem);
    }
    return 0;
}

int scull_release(struct inode *inode, struct file *filp) {
    return 0;
}

static struct scull_qset* scull_follow(struct scull_dev *dev, int index) {
    struct scull_qset *dptr, *head;
    for(head = dptr = dev->data; index >= 0; index--) {
        if(!dptr) {
            dptr = kmalloc(sizeof(struct scull_qset), GFP_KERNEL);
            if(!dptr)
                return NULL;
            dptr->data = NULL;
            dptr->next = NULL;
        }
        if(dev->data == NULL)
            dev->data = dptr;
        head = dptr;
        dptr = dptr->next;
    }
    return head;
}

ssize_t scull_read(struct file *filp, char __user *buf, size_t count, loff_t *fpos) {
    struct scull_dev *dev = (struct scull_dev*)filp->private_data;       
    int quantum = dev->quantum;
    int qset = dev->qset;
    int qset_index, quantum_index, offset;
    struct scull_qset *dptr;
    if(down_interruptible(&dev->sem))
        return -ERESTARTSYS;
    if(*fpos >= dev->size) {
        up(&dev->sem);
        return 0;
    }
    qset_index = (*fpos) / (quantum * qset);
    quantum_index = ((*fpos) % (quantum * qset)) / quantum;
    offset = ((*fpos) % (quantum * qset)) / quantum;
    dptr = scull_follow(dev, qset_index);
    if(!dptr || !dptr->data || !dptr->data[quantum_index]) {
        up(&dev->sem);
        return 0;
    }
    count = SCULL_MIN(SCULL_MIN(count, dev->size - *fpos), quantum - offset);
    if(copy_to_user(buf, dptr->data[quantum_index] + offset, count)) {
        up(&dev->sem);
        return -EFAULT;
    }
    *fpos += count;
    up(&dev->sem);
    return count;
}

ssize_t scull_write(struct file *filp, const char __user *buf, size_t count, loff_t *fpos) {
    struct scull_dev *dev = (struct scull_dev*)filp->private_data;       
    int quantum = dev->quantum;
    int qset = dev->qset;
    int qset_index, quantum_index, offset;
    struct scull_qset *dptr;
    if(down_interruptible(&dev->sem))
        return -ERESTARTSYS;
    qset_index = (*fpos) / (quantum * qset);
    quantum_index = ((*fpos) % (quantum * qset)) / quantum;
    offset = ((*fpos) % (quantum * qset)) / quantum;
    dptr = scull_follow(dev, qset_index);
    if(!dptr) {
        up(&dev->sem);
        return -ENOMEM;
    }
    if(!dptr->data) {
        dptr->data = kmalloc(sizeof(void*) * qset, GFP_KERNEL);
        if(!dptr->data) {
            up(&dev->sem);
            return -ENOMEM;
        }
        memset(dptr->data, 0, sizeof(void*) * qset);
    }
    if(!dptr->data[quantum_index]) {
        dptr->data[quantum_index] = kmalloc(sizeof(void) * quantum, GFP_KERNEL);
        if(!dptr->data[quantum_index]) {
            up(&dev->sem);
            return -ENOMEM;
        }
    }
    count = SCULL_MIN(count, quantum - offset);
    if(copy_from_user(dptr->data[quantum_index] + offset, buf, count)) {
        up(&dev->sem);
        return -EFAULT;
    }
    *fpos += count;
    if(dev->size < *fpos)
        dev->size = *fpos;
    up(&dev->sem);
    return count;
}

loff_t scull_llseek(struct file *filp, loff_t off, int whence) {
    loff_t newpos;
    struct scull_dev *dev = (struct scull_dev*)filp->private_data;
    switch(whence) {
        case SEEK_SET: newpos = off; break;
        case SEEK_CUR: newpos = filp->f_pos + off; break;
        case SEEK_END: newpos = dev->size + off; break;
        default: return -EINVAL;
    }
    if(newpos < 0)
        return -EINVAL;
    filp->f_pos = newpos;
    return newpos;
}

long scull_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    int retval = 0, temp;
    if(_IOC_TYPE(cmd) != SCULL_IOC_MAGIC)
        return -ENOTTY;
    if(_IOC_NR(cmd) >= SCULL_IOC_MAXNR)
        return -ENOTTY;
    if(_IOC_DIR(cmd) & _IOC_READ) {
        retval = !access_ok(VERIFY_WRITE, (void* __user)arg, _IOC_SIZE(cmd));
    } else if(_IOC_DIR(cmd) & _IOC_WRITE) {
        retval = !access_ok(VERIFY_READ, (void* __user)arg, _IOC_SIZE(cmd));  
    }
    if(retval)
        return -EFAULT;
    down(&scull_sem);
    switch(cmd) {
        case SCULL_IOC_RESET:
            scull_quantum = DEFAULT_QUANTUM;
            scull_qset = DEFAULT_QSET;
            break;
        case SCULL_IOCS_QUANTUM:
            if(!capable(CAP_SYS_ADMIN)) {
                retval = -EPERM;
                break;
            }   
            retval = __get_user(scull_quantum, (int* __user)arg);
            break;
        case SCULL_IOCS_QSET:
            if(!capable(CAP_SYS_ADMIN)) {
                retval = -EPERM;
                break;
            }
            retval = __get_user(scull_qset, (int* __user)arg);
            break;
        case SCULL_IOCT_QUANTUM:
            if(!capable(CAP_SYS_ADMIN)) {
                retval = -EPERM;
                break;
            }
            scull_quantum = (int)arg;
            break;
        case SCULL_IOCT_QSET:
            if(!capable(CAP_SYS_ADMIN)) {
                retval = -EPERM;
                break;
            }
            scull_qset = (int)arg;
            break;
        case SCULL_IOCG_QUANTUM:
            retval = __put_user(scull_quantum, (int* __user)arg);
            break;
        case SCULL_IOCG_QSET:
            retval = __put_user(scull_qset, (int* __user)arg);
            break;
        case SCULL_IOCQ_QUANTUM:
            retval = scull_quantum;
            break;
        case SCULL_IOCQ_QSET:
            retval = scull_qset;
            break;
        case SCULL_IOCX_QUANTUM:
            if(!capable(CAP_SYS_ADMIN)) {
                retval = -EPERM;
                break;
            }
            retval = __get_user(temp, (int* __user)arg);
            if(retval)
                break;
            retval = __put_user(scull_quantum, (int* __user)arg);
            if(retval)
                break;
            scull_quantum = temp;
            break;
        case SCULL_IOCX_QSET:
            if(!capable(CAP_SYS_ADMIN)) {
                retval = -EPERM;
                break;
            }
            retval = __get_user(temp, (int* __user)arg);
            if(retval)
                break;
            retval = __put_user(scull_qset, (int* __user)arg);
            if(retval)
                break;
            scull_qset = temp;
            break;
        case SCULL_IOCH_QUANTUM:
            if(!capable(CAP_SYS_ADMIN)) {
                retval = -EPERM;
                break;
            }
            temp = (int)arg;
            retval = scull_quantum;
            scull_quantum = temp;
            break;
        case SCULL_IOCH_QSET:
            if(!capable(CAP_SYS_ADMIN)) {
                retval = -EPERM;
                break;
            }
            temp = (int)arg;
            retval = scull_qset;
            scull_qset = temp;
            break;
        default:
            retval = -ENOTTY;
    }
    up(&scull_sem);
    return retval;
}

int scull_s_open(struct inode *inode, struct file *filp){
    struct scull_dev *dev;
    if(!atomic_dec_and_test(&scull_s_counter)){
        atomic_inc(&scull_s_counter);
        return -EBUSY;
    }
    dev = container_of(inode->i_cdev, struct scull_dev, cdev);
    filp->private_data = (void*)dev;
    if((filp->f_flags & O_ACCMODE) == O_WRONLY) {
        if(down_interruptible(&dev->sem))
            return -ERESTARTSYS;
        scull_trim(dev);
        up(&dev->sem);
    }
    return 0;
}

int scull_s_release(struct inode *inode, struct file *filp){
    atomic_inc(&scull_s_counter);
    return 0;
}


int scull_u_open(struct inode *inode, struct file *filp){
    struct scull_dev *dev;
    spin_lock(&scull_u_lock);
    if(scull_u_counter && scull_u_owner != current_uid().val
            && scull_u_owner != current_euid().val && !capable(CAP_DAC_OVERRIDE)){
        spin_unlock(&scull_u_lock);
        return -EBUSY;
    }
    if(!scull_u_counter){
        scull_u_owner = current_uid().val;
    }
    scull_u_counter++;
    spin_unlock(&scull_u_lock);
    dev = container_of(inode->i_cdev, struct scull_dev, cdev);
    filp->private_data = (void*)dev;
    if((filp->f_flags & O_ACCMODE) == O_WRONLY) {
        if(down_interruptible(&dev->sem))
            return -ERESTARTSYS;
        scull_trim(dev);
        up(&dev->sem);
    }
    return 0;
}

int scull_u_release(struct inode *inode, struct file *filp){
    spin_lock(&scull_u_lock);
    scull_u_counter--;
    spin_unlock(&scull_u_lock);
    return 0;
}

#define scull_w_dev_avaliable() \
    !(scull_w_counter && \
     scull_w_owner != current_uid().val && \
     scull_w_owner != current_euid().val && \
     !capable(CAP_DAC_OVERRIDE))
int scull_w_open(struct inode *inode, struct file *filp){
    struct scull_dev *dev;
    spin_lock(&scull_w_lock);
    while(!scull_w_dev_avaliable()){
        spin_unlock(&scull_w_lock);
        if(filp->f_flags & O_NONBLOCK)
            return -EAGAIN;
        if(wait_event_interruptible(scull_w_wq, scull_w_dev_avaliable()))
            return -ERESTARTSYS;
        spin_lock(&scull_w_lock);
    }
    if(!scull_w_counter){
        scull_w_owner = current_uid().val;
    }
    scull_w_counter++;
    spin_unlock(&scull_w_lock);
    dev = container_of(inode->i_cdev, struct scull_dev, cdev);
    filp->private_data = (void*)dev;
    if((filp->f_flags & O_ACCMODE) == O_WRONLY) {
        if(down_interruptible(&dev->sem))
            return -ERESTARTSYS;
        scull_trim(dev);
        up(&dev->sem);
    }
    return 0;
}

int scull_w_release(struct inode *inode, struct file *filp){
    unsigned int temp_counter = 0;
    spin_lock(&scull_w_lock);
    scull_w_counter--;
    temp_counter = scull_w_counter;
    spin_unlock(&scull_w_lock);
    if(temp_counter == 0)
        wake_up_interruptible_sync(&scull_w_wq);
    return 0;
}

static struct scull_dev* scull_priv_list_lookup(dev_t key){
    struct scull_list_item *lptr;
    list_for_each_entry(lptr, &scull_priv_list, list){
        if(key == lptr->key)
            return &lptr->dev;
    }
    lptr = (struct scull_list_item*)kmalloc(sizeof(struct scull_list_item), GFP_KERNEL);
    if(!lptr)
        return NULL;
    lptr->dev.quantum = scull_quantum;
    lptr->dev.qset = scull_qset;
    lptr->dev.data = NULL;
    lptr->dev.size = 0;
    sema_init(&lptr->dev.sem, 1);
    lptr->key = key;
    list_add(&lptr->list, &scull_priv_list);
    return &lptr->dev;
}

int scull_priv_open(struct inode *inode, struct file *filp){
    struct scull_dev *dev;
    dev_t key;
    if(!current->signal->tty){
        printk(KERN_WARNING "scullpriv: process %s(%d) don't have tty!\n", current->comm, current->pid);
        return -EINVAL;
    }
    key = tty_devnum(current->signal->tty);
    spin_lock(&scull_priv_lock);
    dev = scull_priv_list_lookup(key);
    spin_unlock(&scull_priv_lock);
    if(!dev)
        return -ENOMEM;
    filp->private_data = (void*)dev;
    if((filp->f_flags & O_ACCMODE) == O_WRONLY) {
        if(down_interruptible(&dev->sem))
            return -ERESTARTSYS;
        scull_trim(dev);
        up(&dev->sem);
    }
    return 0;
}

int scull_priv_release(struct inode *inode, struct file *filp){
    return 0;
}

static int __init scull_init(void) {
    dev_t devno;
    int ret;
    int minor_index;
    if(scull_major) {
        devno = MKDEV(scull_major, scull_minor);
        ret = register_chrdev_region(devno, DEVICE_NUM, "scull");
    } else {
        ret = alloc_chrdev_region(&devno, scull_minor, DEVICE_NUM, "scull");
        scull_major = MAJOR(devno);
    }
    if(ret < 0) {
        printk(KERN_WARNING "scull: can't get major(%d)!\n", scull_major);
        return ret;
    }
    sema_init(&scull_sem, 1);
    //four normal devices
    for(minor_index = 0; minor_index <= SCULL_MAX_NORM_DEVNO; minor_index++) {
        devno = MKDEV(scull_major, scull_minor + minor_index);
        cdev_init(&scull_devs[minor_index].cdev, &scull_fops);
        scull_devs[minor_index].cdev.owner = THIS_MODULE;
        scull_devs[minor_index].cdev.ops = &scull_fops;
        scull_devs[minor_index].size = 0;
        scull_devs[minor_index].data = NULL;
        scull_devs[minor_index].quantum = scull_quantum;
        scull_devs[minor_index].qset = scull_qset;
        sema_init(&scull_devs[minor_index].sem, 1);
        ret = cdev_add(&scull_devs[minor_index].cdev, devno, 1);
        if(ret)
            printk(KERN_NOTICE "scull %d add failed (%d)!\n", minor_index, ret);
    }
    //single device
    devno = MKDEV(scull_major, scull_minor + minor_index);
    cdev_init(&scull_devs[minor_index].cdev, &scull_s_fops);
    scull_devs[minor_index].cdev.owner = THIS_MODULE;
    scull_devs[minor_index].cdev.ops = &scull_s_fops;
    scull_devs[minor_index].size = 0;
    scull_devs[minor_index].data = NULL;
    scull_devs[minor_index].quantum = scull_quantum;
    scull_devs[minor_index].qset = scull_qset;
    sema_init(&scull_devs[minor_index].sem, 1);
    ret = cdev_add(&scull_devs[minor_index].cdev, devno, 1);
    if(ret)
        printk(KERN_NOTICE "scull %d add failed (%d)!\n", minor_index, ret);
    //user-bind device
    minor_index++;
    devno = MKDEV(scull_major, scull_minor + minor_index);
    cdev_init(&scull_devs[minor_index].cdev, &scull_u_fops);
    scull_devs[minor_index].cdev.owner = THIS_MODULE;
    scull_devs[minor_index].cdev.ops = &scull_u_fops;
    scull_devs[minor_index].size = 0;
    scull_devs[minor_index].data = NULL;
    scull_devs[minor_index].quantum = scull_quantum;
    scull_devs[minor_index].qset = scull_qset;
    sema_init(&scull_devs[minor_index].sem, 1);
    ret = cdev_add(&scull_devs[minor_index].cdev, devno, 1);
    if(ret)
        printk(KERN_NOTICE "scull %d add failed (%d)!\n", minor_index, ret);
    //user-bind block device
    minor_index++;
    devno = MKDEV(scull_major, scull_minor + minor_index);
    cdev_init(&scull_devs[minor_index].cdev, &scull_w_fops);
    scull_devs[minor_index].cdev.owner = THIS_MODULE;
    scull_devs[minor_index].cdev.ops = &scull_w_fops;
    scull_devs[minor_index].size = 0;
    scull_devs[minor_index].data = NULL;
    scull_devs[minor_index].quantum = scull_quantum;
    scull_devs[minor_index].qset = scull_qset;
    sema_init(&scull_devs[minor_index].sem, 1);
    ret = cdev_add(&scull_devs[minor_index].cdev, devno, 1);
    if(ret)
        printk(KERN_NOTICE "scull %d add failed (%d)!\n", minor_index, ret);
    //tty private device
    minor_index++;
    devno = MKDEV(scull_major, scull_minor + minor_index);
    cdev_init(&scull_devs[minor_index].cdev, &scull_priv_fops);
    scull_devs[minor_index].cdev.owner = THIS_MODULE;
    scull_devs[minor_index].cdev.ops = &scull_priv_fops;
    scull_devs[minor_index].size = 0;
    scull_devs[minor_index].data = NULL;
    scull_devs[minor_index].quantum = scull_quantum;
    scull_devs[minor_index].qset = scull_qset;
    sema_init(&scull_devs[minor_index].sem, 1);
    ret = cdev_add(&scull_devs[minor_index].cdev, devno, 1);
    if(ret)
        printk(KERN_NOTICE "scull %d add failed (%d)!\n", minor_index, ret);
    return 0;
}

static void __exit scull_exit(void) {
    dev_t devno = MKDEV(scull_major, scull_minor);
    int i;
    struct scull_list_item *lptr = NULL, *last_lptr = NULL;
    list_for_each_entry(lptr, &scull_priv_list, list){
        if(last_lptr){
            scull_trim(&last_lptr->dev);
            list_del(&last_lptr->list);
            kfree(last_lptr);
        }
        last_lptr = lptr;
    }
    if(last_lptr){
        scull_trim(&last_lptr->dev);
        list_del(&last_lptr->list);
        kfree(last_lptr);
    }
    for(i = 0; i < DEVICE_NUM; i++) {
        scull_trim(&scull_devs[i]);
        cdev_del(&scull_devs[i].cdev);
    }
    unregister_chrdev_region(devno, DEVICE_NUM);
}

module_init(scull_init);
module_exit(scull_exit);
