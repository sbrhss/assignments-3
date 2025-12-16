/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "aesd-circular-buffer.h"

int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("SBRHSS"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    struct aesd_dev *dev;
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry *entry;
    size_t entry_offset_byte = 0;
    size_t bytes_to_read;
    
    PDEBUG("read %zu bytes with offset %lld", count, *f_pos);
    
    if (mutex_lock_interruptible(&dev->lock)) {
        return -ERESTARTSYS;
    }
    
    entry = aesd_circular_buffer_find_entry_offset_for_fpos(
        &dev->circular_buffer, *f_pos, &entry_offset_byte);
    
    if (entry == NULL) {
        mutex_unlock(&dev->lock);
        return 0;
    }
    
    bytes_to_read = entry->size - entry_offset_byte;
    if (bytes_to_read > count) {
        bytes_to_read = count;
    }
    
    if (copy_to_user(buf, entry->buffptr + entry_offset_byte, bytes_to_read)) {
        mutex_unlock(&dev->lock);
        return -EFAULT;
    }
    
    *f_pos += bytes_to_read;
    retval = bytes_to_read;
    
    mutex_unlock(&dev->lock);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    struct aesd_dev *dev = filp->private_data;
    char *newline_pos;
    char *write_buffer = NULL;
    size_t total_size;
    struct aesd_buffer_entry entry;
    bool found_newline = false;
    
    PDEBUG("write %zu bytes with offset %lld", count, *f_pos);
    
    if (mutex_lock_interruptible(&dev->lock)) {
        return -ERESTARTSYS;
    }
    
    // Allocate buffer for this write
    write_buffer = kmalloc(count, GFP_KERNEL);
    if (!write_buffer) {
        mutex_unlock(&dev->lock);
        return -ENOMEM;
    }
    
    if (copy_from_user(write_buffer, buf, count)) {
        kfree(write_buffer);
        mutex_unlock(&dev->lock);
        return -EFAULT;
    }
    
    // Check for newline
    newline_pos = memchr(write_buffer, '\n', count);
    if (newline_pos) {
        found_newline = true;
    }
    
    // Handle partial write buffer
    if (dev->partial_write_buffer) {
        size_t new_size = dev->partial_write_size + count;
        char *combined = kmalloc(new_size, GFP_KERNEL);
        if (!combined) {
            kfree(write_buffer);
            mutex_unlock(&dev->lock);
            return -ENOMEM;
        }
        memcpy(combined, dev->partial_write_buffer, dev->partial_write_size);
        memcpy(combined + dev->partial_write_size, write_buffer, count);
        kfree(dev->partial_write_buffer);
        kfree(write_buffer);
        dev->partial_write_buffer = combined;
        dev->partial_write_size = new_size;
        
        // Check for newline in combined buffer
        newline_pos = memchr(dev->partial_write_buffer, '\n', dev->partial_write_size);
        if (newline_pos) {
            found_newline = true;
        }
    } else {
        dev->partial_write_buffer = write_buffer;
        dev->partial_write_size = count;
    }
    
    // If we found a newline, add entry to circular buffer
    if (found_newline) {
        // Free old entry if buffer is full
        if (dev->circular_buffer.full) {
            uint8_t old_index = dev->circular_buffer.out_offs;
            if (dev->circular_buffer.entry[old_index].buffptr) {
                kfree((void *)dev->circular_buffer.entry[old_index].buffptr);
            }
        }
        
        entry.buffptr = dev->partial_write_buffer;
        entry.size = dev->partial_write_size;
        aesd_circular_buffer_add_entry(&dev->circular_buffer, &entry);
        
        dev->partial_write_buffer = NULL;
        dev->partial_write_size = 0;
    }
    
    retval = count;
    mutex_unlock(&dev->lock);
    return retval;
}
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device, 0, sizeof(struct aesd_dev));
    
    // Initialize circular buffer
    aesd_circular_buffer_init(&aesd_device.circular_buffer);
    
    // Initialize mutex
    mutex_init(&aesd_device.lock);
    
    // Initialize partial write buffer
    aesd_device.partial_write_buffer = NULL;
    aesd_device.partial_write_size = 0;
    
    result = aesd_setup_cdev(&aesd_device);
    
    if (result) {
        unregister_chrdev_region(dev, 1);
    }
    return result;
}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);
    uint8_t index;
    struct aesd_buffer_entry *entry;
    
    cdev_del(&aesd_device.cdev);
    
    // Free all circular buffer entries
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.circular_buffer, index) {
        if (entry->buffptr) {
            kfree((void *)entry->buffptr);
        }
    }
    
    // Free partial write buffer
    if (aesd_device.partial_write_buffer) {
        kfree(aesd_device.partial_write_buffer);
    }
    
    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
