/**
 * linux/kernel/kvmtrace.c
 * Scott F. H. Kaplan -- sfkaplan@cs.amherst.edu
 *
 * See README.kVMTrace for more information.  This is an entirely new
 * file.
 *
 * kVMTrace-modified file
 */



/* ================================================================== */
/* INCLUDES */

#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/kvmtrace.h>
#include <linux/syscalls.h>
/* ================================================================== */



/* ================================================================== */
/* STATIC VARIABLES */

int kvmtrace_state = 0;
/* ================================================================== */



/* ================================================================== */
/* TRACE LOGGING DEFINITIONS */

/* The task for kvmtraced. */
static struct task_struct* kvmtraced_thread = NULL;

/*
 * A single structure into which information about a kernel event can
 * be recorded before calling emit_kernel_record().
 */
kernel_event_s kernel_event;

/* An array mapping decimal indices to hexidecimal characters. */
const char hex_table [] = {'0', '1', '2', '3', '4', '5', '6', '7',
			   '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

/* The kernel trace's file pointer. */
struct file* kernel_trace_filp = NULL;
/* ================================================================== */



/* ================================================================== */
/* INTERFACE DEFINITIONS */

/* Return values for the activation/deactivation functions. */
#define VMT_SUCCESS 0
#define VMT_ALREADY_TRUE 1
#define VMT_NON_ACTIVATOR 2
#define VMT_OPEN_FAILURE 3
#define VMT_CLOSE_FAILURE 4
#define VMT_FD_LOOKUP_FAILURE 5
/* ================================================================== */



/* ================================================================== */
/**
 * Cite: Lifted and adapted from:
 *       <http://stackoverflow.com/questions/1184274/how-to-read-write-files-within-a-linux-kernel-module>
 */
void open_kernel_trace (void) {

    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    kernel_trace_filp = filp_open("/tmp/kvmtrace.kt",
				  O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE,
				  S_IRUSR | S_IWUSR);
    set_fs(oldfs);
    if(IS_ERR(kernel_trace_filp)) {
        err = PTR_ERR(kernel_trace_filp);
	printk(KERN_ERR "kvmtraced(): Failed to open kernel trace");
    }

}
/* ================================================================== */



/* ================================================================== */
void close_kernel_trace (void) {
    filp_close(kernel_trace_filp, NULL);
}
/* ================================================================== */



/* ================================================================== */
void write_kernel_record () {

    mm_segment_t oldfs;
    int ret;
    loff_t pos = kernel_trace.filp->f_pos;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(kernel_trace_filp, data, size, &pos);
    if (ret != 0) {
	    printk(KERN_ERR "kvmtraced(): Failed write_kernel_trace()");
    }

    set_fs(oldfs);

}
/* ================================================================== */



/* ================================================================== */
void sync_kernel_trace (void) {

    vfs_fsync(kernel_trace_filp, 0);

}
/* ================================================================== */



/* ================================================================== */
/* Schedule kvmtraced if possible. */

static void
schedule_kvmtraced (void) {

	if (kvmtraced_thread != NULL) {
		wake_up_process(kvmtraced_thread);
	}

}
/* ================================================================== */



/* ================================================================== */
/*
 * The entry point for the kvmtraced kernel thread.
 *
 * Set the thread to flush its buffer periodically.
 */

int
kvmtraced (void* unused) {

	/* Log forever. */
	while (1) {

		
		open_kernel_trace();
		if (IS_ERR(kernel_trace.filp)) {

			printk(KERN_NOTICE "kvmtraced: Open failed, sleeping...\n");
			__set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(1000);

		} else {
			printk(KERN_NOTICE "kvmtraced: File opened\n");
			
			/* Try to write something to the kernel trace. */
			write_kernel_trace("Test message!", 13);
			printk(KERN_NOTICE "kvmtraced: Wrote to the kernel trace\n");
			sync_kernel_trace();
			printk(KERN_NOTICE "kvmtraced: Sync'ed kernel trace\n");
			close_kernel_trace();
			printk(KERN_NOTICE "kvmtraced: Closed the kernel trace\n");

			kernel_trace.done = 1;
		}

	}

	printk(KERN_ERR "kvmtraced: ended, and never should!\n");
	return 1;

}
/* ================================================================== */



/* ================================================================== */
/*
 * Initialize a kernel thread that will be responsible for flushing
 * the trace buffers, thus preventing any other thread from having to
 * block on that I/O.
 */

static int __init kvmtraced_init (void) {

	int err = 0;

	printk(KERN_NOTICE "Starting kvmtraced\n");

	/*
	 * Start the kvmtraced thread, which in turn will invoke the
	 * daemon's core function (kvmtraced()).
	 */
	kvmtraced_thread = kthread_run(kvmtraced,
				       &err,
				       "kvmtraced");
	if (err) {
		printk(KERN_ERR "kvmtraced: unable to create thread %i\n", err);
		return err;
	}

	printk(KERN_NOTICE "kvmtraced: initialized\n");
	return VMT_SUCCESS;

}
/* ================================================================== */



/* ================================================================== */
static void __exit kvmtraced_exit (void)
{

	/* Close the kernel trace if it is open.  We do so to achieve a flush. */
	close_kernel_trace();

}
/* ================================================================== */



/* ================================================================== */
/* MODULE STATEMENTS */

module_init(kvmtraced_init);
module_exit(kvmtraced_exit);
/* ================================================================== */



/* ================================================================== */
/*
 * Overrides for Emacs so that we follow Linus's tabbing style.
 * Emacs will notice this stuff at the end of the file and automatically
 * adjust the settings for this buffer only.  This must remain at the end
 * of the file.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-file-style: "linux"
 * End:
 */
/* ================================================================== */
