#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kdev_t.h>
#include <linux/cdev.h>
#include <linux/ioport.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/io.h>
#include <asm/uaccess.h>

MODULE_LICENSE("Dual BSD/GPL");

#define PARPORT_DEVNUM 3
#define DEFAULT_PARPORT_INIT {0x378, 0x278, 0x3bc}
static const unsigned parport_map[PARPORT_DEVNUM] = DEFAULT_PARPORT_INIT;
static struct cdev parport_devs[PARPORT_DEVNUM];
static int short_major, short_minor;

static int short_open(struct inode *inode, struct file *filp){
    filp->private_data = (void*)iminor(inode);
    return 0;
}

static int short_release(struct inode *inode, struct file *filp){
    return 0;
}

#define EXPAND_X(x) x, x, x
static ssize_t short_read(struct file *filp, char __user *buf, size_t count, loff_t *fpos){
    int parport_idx = (int)filp->private_data;
    //data reg : input reg : status reg
    //byte : byte : byte
    char data_reg, status_reg, ctrl_reg;
    data_reg = inb(parport_map[parport_idx]);
    status_reg = inb(parport_map[parport_idx] + 1);
    ctrl_reg = inb(parport_map[parport_idx] + 2);
    printk(KERN_DEBUG "data reg: %x(%d-%c) status reg: %x(%d-%c) ctrl reg: %x(%d-%c)\n", EXPAND_X(data_reg), EXPAND_X(status_reg), EXPAND_X(ctrl_reg));
    //EOF
    return 0;
}

static ssize_t short_write(struct file *filp, const char __user *buf, size_t count, loff_t *fpos){
    //always done
    int parport_idx = (int)filp->private_data;
    char *k_buf = kmalloc(count, GFP_KERNEL);
    char *ptr;
    if(!k_buf){
        printk(KERN_DEBUG "short: short_write kmalloc failed!\n");
        return -ENOMEM;
    }
    if(copy_from_user(k_buf, buf, count)){
        kfree(k_buf);
        printk(KERN_DEBUG "short: short_write copy_from_user failed!\n");
        return -EINVAL;
    }
    ptr = k_buf;
    while(*ptr){
        outb(*(ptr++), parport_map[parport_idx]);
        wmb();
    }
    kfree(k_buf);
    return count;
}

static struct file_operations short_ops = {
    .owner = THIS_MODULE,
    .open = short_open,
    .release = short_release,
    .read = short_read,
    .write = short_write,
};

static int __init short_init(void){
    dev_t devno;
    int ret;
    int i;
    ret = alloc_chrdev_region(&devno, 0, PARPORT_DEVNUM, "short");
    if(ret < 0){
        printk(KERN_DEBUG "short: alloc_chrdev_region failed!\n");
        return ret;
    }
    short_major = MAJOR(devno);
    short_minor = MINOR(devno);
    for(i = 0; i < PARPORT_DEVNUM; i++){
        if(!request_region(parport_map[i], 3, "parport")){
            printk(KERN_DEBUG "short: parport %d unable to request region!\n", i);
            while(i--){
                release_region(parport_map[i], 3);
            }
            unregister_chrdev_region(devno, PARPORT_DEVNUM);
            return -EINVAL;
        }
        devno = MKDEV(short_major, short_minor + i);
        cdev_init(&parport_devs[i], &short_ops);
        parport_devs[i].owner = THIS_MODULE;
        parport_devs[i].ops = &short_ops;
        ret = cdev_add(&parport_devs[i], devno, 1);
        if(ret < 0){
            printk(KERN_DEBUG "short: parport %d unable to be added!\n", i);
            while(i--){
                cdev_del(&parport_devs[i]);
            }
            i = PARPORT_NUM;
            while(i--){
                release_region(parport_map[i], 3);
            }
            unregister_chrdev_region(devno, PARPORT_DEVNUM);
            return ret;
        }
    }
    return 0;
}

static void __exit short_exit(void){
    int i;
    dev_t devno = MKDEV(short_major, short_minor);
    for(i = 0; i < PARPORT_DEVNUM; i++){
        cdev_del(&parport_devs[i]);
        release_region(parport_map[i], 3);
    }
    unregister_chrdev_region(devno, PARPORT_DEVNUM);
}

module_init(short_init);
module_exit(short_exit);
