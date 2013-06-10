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
	int fd;
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
	fd:                    -1,
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

	long write_result = sys_write(kernel_trace.fd, "kvmtraced message\n", 18);
	if (write_result != 0) {
		printk(KERN_WARNING "kvmtraced(): Write failed.\n");
	}

	schedule_timeout(0x8fffffffffffffffL);

	printk(KERN_ERR "kvmtraced() ended, and never should!\n");
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
	static char* kernel_trace_pathname = "/var/log/kernel.trace";

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

	/* Attempt to open the output file. */
	kernel_trace.fd = sys_open(kernel_trace_pathname,
				   O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE,
				   S_IRUSR | S_IWUSR);
	if (kernel_trace.fd == -1) {
		return VMT_OPEN_FAILURE;
	}

	printk(KERN_NOTICE "kvmtraced: initialized\n");
	return VMT_SUCCESS;

}
/* ================================================================== */



/* ================================================================== */
/* MODULE INITIALIZATION */
module_init(kvmtraced_init)
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
