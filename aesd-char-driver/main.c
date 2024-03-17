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
#include <linux/slab.h>
#include "aesdchar.h"


int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Deepak Kapure"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");

    filp->private_data = container_of(inode->i_cdev, struct aesd_dev, cdev);

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    // as nothing new is allocated in open, just return zero
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    size_t rem_bytes;
    size_t entry_offset_byte_rtn    = 0;
    struct aesd_buffer_entry *ent;
    struct aesd_dev *dev = filp->private_data;

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);

    // check input parameters
    if(filp == NULL || buf == NULL || f_pos == NULL) 
        return -EFAULT;
    // grab the mutex
    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;
    ent = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->buffer, 
                                                          (*f_pos),        
                                                          &entry_offset_byte_rtn);
    if(ent != NULL) {
        // check the size of the current buffer entry
        rem_bytes = ent->size - (entry_offset_byte_rtn) ;
        retval = ((rem_bytes > count) ? count : rem_bytes);
        // copy data to user buffer 
        if (copy_to_user(buf, (ent->buffptr + entry_offset_byte_rtn), retval)) {
            retval = -EFAULT;
            goto out;
        }
        // shift offset 
        *f_pos += retval;
        goto out;
    } else {
        // no valid data to read
        retval = 0;
        goto out;
    }
    
    out:
        mutex_unlock(&dev->lock);
        return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    struct aesd_buffer_entry *ret_entry;
    struct aesd_dev *dev = filp->private_data;
    char *write_buf;

    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    
    // check input parameters
    if(filp == NULL || buf == NULL || f_pos == NULL) 
        return -EINVAL;

    // allocate new entry 
    write_buf = kmalloc(count, GFP_KERNEL);
    if (write_buf == NULL)
        return -EFAULT;
    memset(write_buf,0,count);

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    // return if count is zero
    if(count == 0) {
        retval = 0;
        goto out;
    }

    // copy data from user to add to buffer
    if(copy_from_user(write_buf, buf, count)) {
        retval = -EFAULT;
        goto out;
    }

    // update teh working entry in dev
    dev->w_entry.buffptr = krealloc(dev->w_entry.buffptr, (dev->w_entry.size+count), GFP_KERNEL);
    if (dev->w_entry.buffptr == NULL) {
        retval = -EFAULT;
        goto out;
    }

    // copy data to working entry 
    memcpy(((dev->w_entry.buffptr) + dev->w_entry.size), write_buf, count);
    dev->w_entry.size += count;
    retval = count;

    // check for new line character
    if(memchr(write_buf, '\n', count) != NULL) {
        // add to circular buffer
        ret_entry = aesd_circular_buffer_add_entry(&dev->buffer, &dev->w_entry);

        // free overwritten buffer entries
        if(ret_entry != NULL)
            kfree(ret_entry);

        // clear working buffer
        dev->w_entry.buffptr = NULL;
        dev->w_entry.size    = 0;

        // update return count
        retval = count;
        goto out;
    }

    out:
        mutex_unlock(&dev->lock);
        kfree(write_buf);
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
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    // initialize buffer
    aesd_circular_buffer_init(&aesd_device.buffer);
    aesd_device.w_entry.buffptr = NULL;
    aesd_device.w_entry.size    = 0;
    // initialize mutex
    mutex_init(&aesd_device.lock);
    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);
    uint8_t idx=0;
    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */
    // free allocated buffer entries

    // free aesd_device
    if(aesd_device.buffer.full) {
        for(idx=0; idx<AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; idx++) {
            kfree(&aesd_device.buffer.entry[idx].buffptr);
            kfree(&aesd_device.buffer.entry[idx]);
        }
    } else {
        for(idx=0; idx<(aesd_device.buffer.in_offs-1); idx++) {
            kfree(&aesd_device.buffer.entry[idx].buffptr);
            kfree(&aesd_device.buffer.entry[idx]);
        }
    }
    // check buffptr if not null
    if(aesd_device.w_entry.buffptr != NULL)
        kfree(&aesd_device.w_entry.buffptr);
    unregister_chrdev_region(devno, 1);
}


module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
