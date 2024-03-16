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
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Deepak Kapure"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    /**
     * TODO: handle open
     */
    // assign private data to the aesd_device type
    struct aesd_dev *dev;        

    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;    /* for other methods */

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
    struct aesd_dev *dev = filp->private_data;

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);

    // check input parameters
    if(filp == NULL || buf == NULL || f_pos == NULL) 
        return -EFAULT;
    // grab the mutex
    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;
    size_t entry_offset_byte_rtn    = 0;
    struct aesd_buffer_entry *ent = aesd_circular_buffer_find_entry_offset_for_fpos(filp->buffer, 
                                                                                    (size_t)(&f_pos),        
                                                                                    &entry_offset_byte_rtn);
    if(ent != NULL) {
        // check the size of the current buffer entry
        size_t rem_bytes = ent->size - (entry_offset_byte_rtn + 1) ;
        retval = (ssize_t)((rem_bytes > count) ? count : rem_bytes);
        // copy data to user buffer 
        if (copy_to_user(buf, ent + entry_offset_byte_rtn, retval)) {
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
    struct aesd_dev *dev = filp->private_data;

    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    
    // check input parameters
    if(filp == NULL || buf == NULL || f_pos == NULL) 
        return -EFAULT;
    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;
    if(count == 0) {
        retval = 0;
        goto out;
    }
    // get data from user buffer
    if(dev->buffptr != NULL) {
        // realloc previous allotment
        dev->buffptr = krealloc(dev->buffptr, (dev->inprgs_aesd_write_val + count),
                                GFP_KERNEL);
    } else {
        // allocate new entry 
        char *dev->buffptr = kmalloc(sizeof(char * count), GFP_KERNEL);
        if (dev->buffptr == NULL){
            retval = -EFAULT
            goto out;
        }
        memset(&dev->buffptr,0,sizeof(char * count));
    }
    // copy data from user to add to buffer
    if(copy_from_user((dev->buffptr + dev->inprgs_aesd_write_val), buf, count)) {
        retval = -EFAULT;
        goto out;
    }
    dev->inprgs_aesd_write_val += count;
    // check for new line character
    if(memchr(dev->buffptr, '\n', count) != NULL) {
        // create an entry and fill size and pointer for string
        aesd_buffer_entry *entry = kmalloc(sizeof(aesd_buffer_entry), GFP_KERNEL);
        if (entry == NULL) {
            retval = -EFAULT
            goto out;
        }
        entry->buffptr = dev->buffptr;
        entry->size = dev->inprgs_aesd_write_val;
        // add to circular buffer
        aesd_buffer_entry *ret_entry = aesd_circular_buffer_add_entry(dev->buffer, entry);
        if(ret_entry != NULL)
            kfree(ret_entry);
        // clear inprgs val and pointer to dynamic buffer
        dev->buffptr = NULL;
        dev->inprgs_aesd_write_val = 0;
    }

    retval = dev->inprgs_aesd_write_val;
    goto out;

    out:
        mutex_unlock(&dev->lock);init
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
    aesd_device.buffptr = NULL;
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

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */
    // free allocated buffer entries

    // free aesd_device
    if(aesd_device.buffer.full) {
        for(uint8_t idx=0; idx<AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; idx++) {
            kfree(aesd_device.buffer.entry[idx].buffptr);
            kfree(aesd_device.buffer.entry[idx]);
        }
    } else {
        for(uint8_t idx=0; idx<(aesd_device.buffer.in_offs-1); idx++) {
            kfree(aesd_device.buffer.entry[idx].buffptr);
            kfree(aesd_device.buffer.entry[idx]);
        }
    }
    // check buffptr if not null
    if(aesd_device.buffptr != NULL)
        kfree(aesd_device.buffptr);
    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
