/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-cryptodev device 
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device 
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor){
			debug("heyo");
			goto out;
		}
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	unsigned int len;
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	unsigned int *syscall_type;
	int *host_fd, retval, num_out, num_in;
	struct scatterlist syscall_type_sg, host_fd_sg, *sg[2]; //0 -> syscalltype, 1-> host
	unsigned long flags;
	
	
	debug("Entering");
	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_OPEN;
	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = -1;

	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto fail;

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor", 
		      iminor(inode));
		ret = -ENODEV;
		goto fail;
	}

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}
	crof->crdev = crdev;
	crof->host_fd = -1;
	filp->private_data = crof;

	/**
	 * We need two sg lists, one for syscall_type and one to get the 
	 * file descriptor from the host.
	 **/
	num_out=0;
	num_in=0;

	spin_lock_irqsave(&(crdev->spinlock), flags);
	
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sg[num_out++] = &syscall_type_sg;
	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sg[num_out + num_in++] = &host_fd_sg;

	//add data in VirtQueue
	//lock


	
	retval = virtqueue_add_sgs(crdev->vq, sg, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
	if (retval < 0){
		debug("virtqueue_add error");
		ret = retval;
		goto fail;
	}
	
	//kick
	virtqueue_kick(crdev->vq);

	
	/**
	 * Wait for the host to process our data.
	 **/
	while(virtqueue_get_buf(crdev->vq, &len) == NULL);
	
	spin_unlock_irqrestore(&(crdev->spinlock), flags);
	
	/* If host failed to open() return -ENODEV. */
		
	if(host_fd < 0){
		debug("Invalid host_fd");
		ret = -ENODEV;
		goto fail;
	}

	crof->host_fd = *host_fd;
	
	

fail:
	debug("Leaving");
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	unsigned int *syscall_type;
	struct scatterlist syscall_type_sg, host_fd_sg, *sg[2];
	unsigned long flags;
	int num_out, num_in, retval;
	unsigned int len;


	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_CLOSE;

	/**
	 * Send data to the host.
	 **/
	num_out=0;
	num_in=0;

	sg_init_one(&syscall_type_sg, syscall_type, sizeof(syscall_type));
	sg[num_out++] = &syscall_type_sg;
	sg_init_one(&host_fd_sg, &(crof->host_fd), sizeof(&(crof->host_fd)));
	sg[num_out++] = &host_fd_sg;

	//lock
	//add data to queue
	spin_lock_irqsave(&(crdev->spinlock), flags);
	
	retval = virtqueue_add_sgs(crdev->vq, sg, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
	if (retval < 0){
		debug("release virtqueue_add_sgs error");
		ret = retval;
		goto exit;
	}
	
	virtqueue_kick(crdev->vq);


	/**
	 * Wait for the host to process our data.
	 **/

	while(virtqueue_get_buf(crdev->vq, &len) == NULL);
	
	spin_unlock_irqrestore(&(crdev->spinlock), flags);

	
	kfree(crof);
exit:
	debug("Leaving");
	return ret;

}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, 
                                unsigned long arg)
{
	long ret = 0;
	int err, retval;
	unsigned long flags;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, ioctl_cmd_sg, host_fd_sg, sess_sg, ses_sg, key_sg, crypt_sg, host_result_sg, iv_sg, src_sg, dst_sg, *sgs[8];
	struct session_op * sess;
	struct crypt_op * cryp;
	__u32 *ses;
	
	unsigned int num_out, num_in, len;
#define MSG_LEN 100
	unsigned char *iv, *src, *key, *dst=NULL;
	unsigned int *syscall_type, *ioctl_cmd;

	debug("Entering");

	/**
	 * Allocate all data that will be sent to the host.
	 **/
	//output_msg = kzalloc(MSG_LEN, GFP_KERNEL);
	//input_msg = kzalloc(MSG_LEN, GFP_KERNEL);
	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_IOCTL;
	
	sess = kzalloc(sizeof(struct session_op), GFP_KERNEL);
	ses = kzalloc(sizeof(*ses), GFP_KERNEL);
	cryp = kzalloc(sizeof(struct crypt_op), GFP_KERNEL);
	ioctl_cmd = kzalloc(sizeof(*ioctl_cmd), GFP_KERNEL);
	*ioctl_cmd = cmd;
	*ses = sess->ses;	

	num_out = 0;
	num_in = 0;	


	/**
	 *  These are common to all ioctl commands.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	
	sg_init_one(&ioctl_cmd_sg, ioctl_cmd, sizeof(*ioctl_cmd));
	sgs[num_out++] = &ioctl_cmd_sg;

	sg_init_one(&host_fd_sg, &(crof->host_fd), sizeof(crof->host_fd));
	sgs[num_out++] = &host_fd_sg;

	/**
	 *  Add all the cmd specific sg lists.
	 **/
	

	switch (cmd) {
	case CIOCGSESSION:
		debug("CIOCGSESSION");

		retval = copy_from_user(sess, (struct session_op *)arg, sizeof(*sess));
		if (retval != 0){
			debug("CIOCGSESSION: copy from user - sess");
			ret = 1 ;
			goto out;
		}
		
		key = kzalloc(sess->keylen, GFP_KERNEL);
		retval = copy_from_user(key, sess->key, sess->keylen);
		if (retval != 0){
			debug("CIOCGSESSION: copy from user - key");
			ret = 1 ;
			goto out;
		}
	
		sg_init_one(&key_sg, key, sess->keylen);
		sgs[num_out++] = &key_sg;

		sg_init_one(&sess_sg, sess, sizeof(*sess));
		sgs[num_out + num_in++] = &sess_sg;

		sg_init_one(&host_result_sg, &retval, sizeof(retval));
		sgs[num_out + num_in++] = &host_result_sg;
		break;

	case CIOCFSESSION:
		debug("CIOCFSESSION");
		retval = copy_from_user(&(sess->ses), (__u32 *) arg, sizeof(__u32));
		if (retval != 0){
			debug("CIOCFSESSION: copy from user");
			ret = 1 ;
			goto out;
		}
		sg_init_one(&ses_sg, ses, sizeof(*ses));
		sgs[num_out++] = &ses_sg;
	
		sg_init_one(&host_result_sg, &retval, sizeof(retval));
		sgs[num_out + num_in++] = &host_result_sg;

		break;

	case CIOCCRYPT:
		debug("CIOCCRYPT");
		retval = copy_from_user(cryp, (struct crypt_op *) arg, sizeof(struct crypt_op));
		if (retval != 0){
			debug("CIOCRYPT: copy from user");
			ret = 1 ;
			goto out;
		}

		iv = kzalloc(EALG_MAX_BLOCK_LEN, GFP_KERNEL);
		retval = copy_from_user(iv, ((struct crypt_op *) arg)->iv, EALG_MAX_BLOCK_LEN);
		if (retval != 0){
			debug("CIOCCRYPT: copy from user");
			ret = 1 ;
			goto out;
		}

		src = kzalloc(cryp->len, GFP_KERNEL);
		retval = copy_from_user(src, ((struct crypt_op *) arg)->src, cryp->len);
		if (retval != 0){
			debug("CIOCCRYPT: copy from user");
			ret = 1 ;
			goto out;
		}		
		
		dst = kzalloc(cryp->len, GFP_KERNEL);

		sg_init_one(&crypt_sg, cryp, sizeof(*cryp));
		sgs[num_out++] = &crypt_sg;

		sg_init_one(&iv_sg, iv,  EALG_MAX_BLOCK_LEN);
		sgs[num_out++] = &iv_sg;

		sg_init_one(&src_sg, src, cryp->len);
		sgs[num_out++] = &src_sg;

		sg_init_one(&dst_sg, dst, cryp->len);
		sgs[num_out + num_in++] = &dst_sg;
			
		sg_init_one(&host_result_sg, &retval, sizeof(retval));
		sgs[num_out + num_in++] = &host_result_sg;


		
		break;

	default:
		debug("Unsupported ioctl command");

		break;
	}


	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	/* ?? Lock ?? */
	spin_lock_irqsave(&(crdev->spinlock), flags);

	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;
	
	spin_unlock_irqrestore(&(crdev->spinlock), flags);


	if(retval < 0){
		ret=-EIO;
		debug("Ioctl");
		goto out;
	}
	if (cmd == CIOCCRYPT){
		retval = copy_to_user(((struct crypt_op *)arg)->dst, dst, cryp->len);
		if (retval != 0){
			debug("CIOCCRYPT: copy to user");
			ret = 1 ;
			goto out;
		}
	}
	if (cmd == CIOCGSESSION){
		retval = copy_to_user((struct session_op *) arg, sess, sizeof(*sess));
		if (retval != 0){
			debug("CIOCGSESSION: copy to user");
			ret = 1 ;
			goto out;
		}
	}
	
	
out:
	kfree(syscall_type);
	kfree(sess);
	kfree(cryp);

	debug("Leaving");

	return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf, 
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;
	
	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
