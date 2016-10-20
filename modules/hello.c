#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/moduleparam.h>
MODULE_LICENSE("Dual BSD/GPL");

static char *name = "default";
static int nums = 5;

static int __init hello_init(void) {
    int i;
    for(i = 0; i < nums; i++) {
        printk(KERN_ALERT "Hello Modules from %s (%i)!\n", current->comm, current->pid);
    }
    return 0;
}

static void __exit hello_exit(void) {
    printk(KERN_ALERT "Bye Modules!\n");
}

module_param(name, charp, S_IRUGO);
module_param(nums, int, S_IRUGO);
module_init(hello_init);
module_exit(hello_exit);
