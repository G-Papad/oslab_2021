/*
 * lunix-chrdev.c
 *
 * Implementation of character devices
 * for Lunix:TNG
 *
 * George Papadoulis <geopapadoulis@gmial.com>
 * Christina Proestaki <chri.proe@gmail.com>
 *
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mmzone.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>

#include "lunix.h"
#include "lunix-chrdev.h"
#include "lunix-lookup.h"

/*
 * Global data
 */
struct cdev lunix_chrdev_cdev;

/*
 * Just a quick [unlocked] check to see if the cached
 * chrdev state needs to be updated from sensor measurements.
 */
static int lunix_chrdev_state_needs_refresh(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;
	
	WARN_ON ( !(sensor = state->sensor));
	/* ? */
	//refreshed when 
	
	if(sensor->msr_data[state->type]->last_update /*sensor last update*/> state->buf_timestamp /* chrdev_data_buf last update*/)
		return 1;
	return 0;
}

/*
 * Updates the cached state of a character device
 * based on sensor data. Must be called with the
 * character device state lock held.
 */
static int lunix_chrdev_state_update(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;
	uint32_t tempor_data, div, mod, last_update;
	unsigned long flags;

	debug("leaving\n");

	/*
	 * Grab the raw data quickly hold the
	 * spinlock for as little as possible.
	 */
	/* ? */
	sensor = state->sensor;
	spin_lock_irqsave(&sensor->lock, flags);
	tempor_data = sensor->msr_data[state->type]->values[0]; 
	last_update = sensor->msr_data[state->type]->last_update;
	spin_unlock_irqrestore(&sensor->lock, flags);
	/* Why use spinlocks? See LDD3, p. 119 */

	/*
	 * Any new data available?
	 */
	/* ? */
	if(!lunix_chrdev_state_needs_refresh(state)){
		return -EAGAIN;
	}

	/*
	 * Now we can take our time to format them,
	 * holding only the private state semaphore
	 */
	state->buf_timestamp = last_update;
	switch(state->type){
			case BATT:
				tempor_data = lookup_voltage[tempor_data];
				break;
			case TEMP:
				tempor_data = lookup_temperature[tempor_data];
				break;
			case LIGHT:
				tempor_data = lookup_light[tempor_data];
				break;
			default:
				debug("ERROR_update: Wrong type");
				return -1;
		}

	div = tempor_data / 1000; //morfi einai xx.yyy
	mod = tempor_data % 1000;

	//writing the data to state->buf_data
	if(((state->buf_lim) = snprintf(state->buf_data, LUNIX_CHRDEV_BUFSZ, "%lu.%lu\n", (unsigned long)div, (unsigned long)mod)) > LUNIX_CHRDEV_BUFSZ){
		debug("ERROR_update: Buffer overflow");
		return -1;
	}

	debug("leaving\n");
	return 0;
}

/*************************************
 * Implementation of file operations
 * for the Lunix character device
 *************************************/

static int lunix_chrdev_open(struct inode *inode, struct file *filp)
{
	/* Declarations */
	/* ? */
	int ret, no, type, minor_number;
	struct lunix_chrdev_state_struct *private_state;
	debug("entering\n");
	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto out;

	//connect the f_op of file with the ops of inode struct
	filp->f_op = (inode->i_cdev)->ops;

	/*
	 * Associate this open file with the relevant sensor based on
	 * the minor number of the device node [/dev/sensor<NO>-<TYPE>]
	 */

	minor_number = iminor(inode);
	no = minor_number / 8;
	type = minor_number % 8;
/*
	if(type >= N_LUNIX_MSR ){ //types : {0: batt , 1: temp, 2: light}
		ret -ENODEV;  //ERROR: wrong minor number
		goto out;
	}
*/	
	/* Allocate a new Lunix character device private state structure */
	/* ? */
	private_state = kmalloc(sizeof(*private_state),GFP_KERNEL);
	private_state->type = type;
	private_state->sensor= lunix_sensors+no;
	private_state->buf_timestamp=0;
	private_state->buf_lim=0;
	/*private_state->mode=1; //blocking

	if(state->mode){
		filp->flags &= ~O_NONBLOCK;
	}
	*/
	sema_init(&(private_state->lock), 1);

	filp->private_data = private_state; //for access from other fun

out:
	debug("leaving, with ret = %d\n", ret);
	return ret;
}

static int lunix_chrdev_release(struct inode *inode, struct file *filp)
{
	/* ? */
	//deallocate from private data the private_state
	kfree(filp->private_data);
	return 0;
}

static long lunix_chrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	/* Why? */
	return -EINVAL;
}

static ssize_t lunix_chrdev_read(struct file *filp, char __user *usrbuf, size_t cnt, loff_t *f_pos)
{
	ssize_t ret;

	struct lunix_sensor_struct *sensor;
	struct lunix_chrdev_state_struct *state;

	state = filp->private_data; //state->trexousa katastasi tis siskevis
	WARN_ON(!state);

	sensor = state->sensor;
	WARN_ON(!sensor);

	/* Lock? */
	if(down_interruptible(&state->lock)){
		return -ERESTARTSYS;
	}

	/*
	 * If the cached character device state needs to be
	 * updated by actual sensor data (i.e. we need to report
	 * on a "fresh" measurement, do so
	 */
	if (*f_pos == 0) {
		while (lunix_chrdev_state_update(state) == -EAGAIN) {
			/* ? */
			up(&(state->lock));
			if(filp->f_flags & O_NONBLOCK)
				return -EAGAIN;
			//debug("reading: going to sleep");
			/* The process needs to sleep */
			/* See LDD3, page 153 for a hint */
			if(wait_event_interruptible(sensor->wq, lunix_chrdev_state_needs_refresh(state)))
				return -ERESTARTSYS;
			if(down_interruptible(&state->lock))
				return -ERESTARTSYS;
		}
	}
	/* End of file */
	/* ? */
	//buf_lim -> shows EOF
	if(state->buf_lim == 0){ //nothing to read - EOF
		ret = 0; //return the number of bytes that we read
		goto out;
	}
	/* Determine the number of cached bytes to copy to userspace */
	/* ? */
	if(cnt > state->buf_lim - *f_pos)
		cnt = state->buf_lim - *f_pos;
//	cnt = min(cnt, (state->buf_lim - *f_pos)); //cnt
	if(copy_to_user(usrbuf, state->buf_data + *f_pos, cnt)){
		up(&state->lock);
		return -EFAULT;
	}
	/* Auto-rewind on EOF mode? */
	/* ? */
	*f_pos += cnt;
	if(*f_pos >= state->buf_lim){
		*f_pos=0;
	}
	ret = cnt; //cnt is the bytes that we read

out:
	/* Unlock? */
	up(&state->lock);
	return ret;
}

static int lunix_chrdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	return -EINVAL;
}

static struct file_operations lunix_chrdev_fops = 
{
        .owner          = THIS_MODULE,
	.open           = lunix_chrdev_open,
	.release        = lunix_chrdev_release,
	.read           = lunix_chrdev_read,
	.unlocked_ioctl = lunix_chrdev_ioctl,
	.mmap           = lunix_chrdev_mmap
};

int lunix_chrdev_init(void)
{
	/*
	 * Register the character device with the kernel, asking for
	 * a range of minor numbers (number of sensors * 8 measurements / sensor)
	 * beginning with LINUX_CHRDEV_MAJOR:0
	 */
	int ret;
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3; 
	
	debug("initializing character device\n");
	cdev_init(&lunix_chrdev_cdev, &lunix_chrdev_fops);
	lunix_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0); //... bits a->ma, b->mi
	/*
		Αποθηκεύει τον αριθμό τον device numbers που μας απασχολούν
	 */
	/* register_chrdev_region? */
	ret = register_chrdev_region(dev_no, lunix_minor_cnt+2/*τελευταια μέτρηση*/, "lunixTNG");
	if (ret < 0) {
		debug("failed to register region, ret = %d\n", ret);
		goto out;
	}	
	/*  
		add a char device to the system
		δίνει την δυνατότητα στον πυρήνα να καλέσει τα operations
	*/
	/* cdev_add? */
	ret = cdev_add(&lunix_chrdev_cdev, dev_no, lunix_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device\n");
		goto out_with_chrdev_region;
	}
	debug("completed successfully\n");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
out:
	return ret;
}

void lunix_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
		
	debug("entering\n");
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	cdev_del(&lunix_chrdev_cdev);
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
	debug("leaving\n");
}
