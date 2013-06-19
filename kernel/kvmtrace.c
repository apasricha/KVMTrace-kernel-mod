/**
 * linux/mm/kvmtrace.c
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

/*
 * Each trace is represented by a structure that holds buffer space
 * into which records can be stored, as well as the file structure and
 * activator file descriptor information to which the buffered data is
 * eventually written.  The buffer are organized circularly, and
 * flushed at the first opportunity.  All buffer space is allocated at
 * once.  This structure is needed for two reasons:
 *
 *   (a) The kernel trace may fill more than 4 MB -- the
 *       single-allocation limit within the kernel.  Thus, one buffer
 *       space will not do.
 *
 *   (b) To avoid race problems caused by a thread that blocks when
 *       flushing a buffer, a new buffer space is used as soon as a
 *       thread attempts such a write operation.  Each such buffer is
 *       marked as needing to be flushed, so we can detect when we've
 *       exhausted the buffer space.
 *
 *  Note that we also choose to use _slightly less_ than a power-of-2
 *  buffer size, thus allowing room for any allocator headers that may
 *  be part of the blocks allocated to each buffer.  Thus, each buffer
 *  should fit nicely on a integral, power-of-2-aligned space if the
 *  allocator likes it that way.
 */

/* Constants for the buffers. */
#define KERNEL_TRACE_MAX_RECORD_SIZE (filename_buffer_size + 64)
#define KERNEL_TRACE_BUFFER_SIZE (127 * 1024)
#define NUMBER_KERNEL_TRACE_BUFFERS 64

/* An array mapping decimal indices to hexidecimal characters. */
const char hex_table [] = {'0', '1', '2', '3', '4', '5', '6', '7',
			   '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

/* The structure of a single buffer of trace data. */
struct trace_buffer {

	char* content;
	int index;
	int need_to_flush;

};

/* The structure used to manage a given trace (buffers and output). */
struct trace {

	struct trace_buffer** buffers;
	struct trace_buffer* current_buffer;
	int current_index;
	int first_unflushed_index;
	int buffer_size;
	int number_buffers;
	struct file* filp;
	int done;
	char name[16];

};

/* The kernel trace structure, initialized. */
struct trace kernel_trace = {
	buffers:               NULL,
	current_buffer:        NULL,
	current_index:         0,
	first_unflushed_index: 0,
	buffer_size:           KERNEL_TRACE_BUFFER_SIZE,
	number_buffers:        NUMBER_KERNEL_TRACE_BUFFERS,
	filp:                  NULL,
	done:                  0,
	name:                  "kernel"
};
/* ================================================================== */



/* ================================================================== */
/* INTERFACE DEFINITIONS */

/* Return values for the activation/deactivation functions. */
#define VMT_SUCCESS 0
#define VMT_ALREADY_TRUE 1
#define VMT_NON_ACTIVATOR 2
#define VMT_REFERENCE_TRACING_ACTIVE 3
#define VMT_OPEN_FAILURE 4
#define VMT_CLOSE_FAILURE 5
#define VMT_FD_LOOKUP_FAILURE 6
#define VMT_BUFFER_OVERFULL 7
#define VMT_FAILED_BUFFER_DUMP 8
#define VMT_INCOMPLETE_BUFFER_DUMP 9
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
    kernel_trace.filp = filp_open("/tmp/kvmtrace.kt",
				  O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE,
				  S_IRUSR | S_IWUSR);
    set_fs(oldfs);
    if(IS_ERR(kernel_trace.filp)) {
        err = PTR_ERR(kernel_trace.filp);
	printk(KERN_ERR "kvmtraced(): Failed to open kernel trace");
    }

}
/* ================================================================== */



/* ================================================================== */
void close_kernel_trace (void) {
    filp_close(kernel_trace.filp, NULL);
}
/* ================================================================== */



/* ================================================================== */
void write_kernel_trace (unsigned char* data, unsigned int size) {

    mm_segment_t oldfs;
    int ret;
    loff_t pos = kernel_trace.filp->f_pos;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(kernel_trace.filp, data, size, &pos);
    if (ret != 0) {
	    printk(KERN_ERR "kvmtraced(): Failed write_kernel_trace()");
    }

    set_fs(oldfs);

}
/* ================================================================== */



/* ================================================================== */
void sync_kernel_trace (void) {

    vfs_fsync(kernel_trace.filp, 0);

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

	printk(KERN_NOTICE "In kvmtraced\n");

	/* Try repeatedly until it works. */
	while (!kernel_trace.done) {

		/* Attempt to open the output file. */
		printk(KERN_NOTICE "kvmtraced: Trying to open...\n");
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
