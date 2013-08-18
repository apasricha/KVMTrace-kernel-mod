/**
 * linux/kernel/kvmtrace.c
 * Scott F. H. Kaplan -- sfkaplan@cs.amherst.edu
 *
 * See README.kVMTrace for more information.  This is an entirely new
 * file.
 *
 * kVMTrace-modified file
 **/



/* ================================================================== */
/* INCLUDES */

#include <asm/msr.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/kvmtrace.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
/* ================================================================== */



/* ================================================================== */
/* STATIC VARIABLES */

int kvmtrace_state = 0;
uint32_t references_per_jiffy = 1000000000 / HZ;
/* ================================================================== */



/* ================================================================== */
/* TRACE LOGGING DEFINITIONS */

/* The task for kvmtraced. */
struct task_struct* kvmtraced_thread = NULL;

/*
 * A single structure into which information about a kernel event can
 * be recorded before calling emit_kernel_record().
 */
kernel_event_s kernel_event;

/* An array mapping decimal indices to hexidecimal characters. */
const char hex_table [] = {'0', '1', '2', '3', '4', '5', '6', '7',
			   '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

/* The kernel trace's file pointer. */
struct file* kt_filp = NULL;

/*
 * The kernel trace's construction buffer.  New records are assembled
 * into this space; when it is nearly full, the kvmtraced thread
 * flushes it.
 */
char* kt_buffer = NULL;

/* The current index into the kernel trace buffer. */
int kt_i = 0;

/* The size of the kernel trace buffer. */
#define KT_BUFFER_SIZE (1024 * 1024) // 1024 KB * 1024 B/KB = 1 MB

/*
 * The maximum size of a kernel trace record (calculated, but not with
 * particular care, so a bit of conservative padding included.)
 */
#define KT_MAX_RECORD_SIZE 256 // B
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
/*
 * Convert an unsigned integer into a hexidecimal text representation.
 * The caller must provide a buffer space and an index into that
 * buffer space, where the index will be returned pointing to the
 * first byte in the buffer beyond what was added by this function.
 * Note that the caller must also specify the length of the integer,
 * since short, long, and quad-long types can be handled.
 */

static void
int_to_string (char* buffer,
	       int* buffer_index,
	       unsigned char* value,
	       unsigned int value_size)
{

	/*
	 * Loop through the bytes of the value.  Assume (for
	 * i386/amd64) little-endianness.
	 */
	int index;
	int non_zero_encountered = 0;
	for (index = value_size - 1;
	     index >= 0;
	     index--) {

		/*
		 * Grab the value two nybbles composing the current
		 * byte.
		 */
		unsigned int lower_nybble = value[index] & 0xf;
		unsigned int upper_nybble = value[index] >> 4;

		/*
		 * If a non-zero value has previously been
		 * encountered, or this value is non-zero, then we add
		 * the upper nybble to the buffer.
		 */
		if ((non_zero_encountered) || (upper_nybble != 0)) {
			buffer[(*buffer_index)++] =
				hex_table[upper_nybble];
			non_zero_encountered = 1;
		}

		/* Same, but for the lower nybble. */
		if ((non_zero_encountered) || (lower_nybble != 0)) {
			buffer[(*buffer_index)++] =
				hex_table[lower_nybble];
			non_zero_encountered = 1;
		}
	}

	/*
	 * If the value was all zeroes, emit a single zero
	 * character.
	 */
	if (!non_zero_encountered) {
		buffer[(*buffer_index)++] = '0';
	}

}
/* ================================================================== */



/* ================================================================== */
/*
 * Copy a string from one buffer to another.  The caller must provide
 * the destination buffer space and an index into that buffer space,
 * where the index will be returned pointing to the first byte in the
 * buffer beyond what was added by this function.  The source string
 * must be null-terminated.  The destination buffer must be large
 * enough to hold the source.
 */

void
string_to_string (char* buffer,
		  int* buffer_index,
		  char* source)
{

	/*
	 * Loop through the bytes of the source string until a null
	 * character is encountered.
	 */
	while (*source != '\0') {

		buffer[*buffer_index] = *source;
		(*buffer_index)++;
		source++;

	}

}
/* ================================================================== */



/* ================================================================== */
/**
 * Cite: Lifted and adapted from:
 *       <http://stackoverflow.com/questions/1184274/how-to-read-write-files-within-a-linux-kernel-module>
 */
void
open_kernel_trace (void)
{

    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    kt_filp = filp_open("/tmp/kvmtrace.kt",
				  O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE,
				  S_IRUSR | S_IWUSR);
    set_fs(oldfs);
    if(IS_ERR(kt_filp)) {
        err = PTR_ERR(kt_filp);
	printk(KERN_ERR "kvmtraced(): Failed to open kernel trace");
    }

}
/* ================================================================== */



/* ================================================================== */
void
close_kernel_trace (void)
{

    filp_close(kt_filp, NULL);

}
/* ================================================================== */



/* ================================================================== */
/**
 * Write the buffered kernel events to the kernel trace immediately.
 **/

void
flush_kernel_trace (void)
{

    mm_segment_t old_fs;
    int ret;
    loff_t pos;

    /*
     * If this is the first call to flush the buffer, then open the
     * output file.  If the open fails, return without flushing, since
     * the system may not yet be ready to open the trace file.
     */
    if (kt_filp == NULL) {
	    open_kernel_trace();
	    if (IS_ERR(kt_filp)) {
		    printk(KERN_NOTICE "kvmtraced: Failed open, skipping emit.\n");
		    kt_filp = NULL;
		    return;
	    }
    }
    pos = kt_filp->f_pos;

    /* Lock the buffer, flush it, and then unlock it. */
    old_fs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(kt_filp, kt_buffer, kt_i, &pos);
    if (ret != 0) {
	    printk(KERN_ERR "kvmtraced(): Failed emit_kernel_trace()");
    }

    set_fs(old_fs);
    kt_i = 0;

}
/* ================================================================== */



/* ================================================================== */
/* Schedule kvmtraced if possible. */

static void
schedule_kvmtraced (void)
{

	if (kvmtraced_thread != NULL) {
		wake_up_process(kvmtraced_thread);
	}

}
/* ================================================================== */



/* ================================================================== */
/*
 * Given the mode bits from an inode, return a value that indicates
 * just the file type (file, pipe, device, or socket).
 */

file_type_t determine_file_type (umode_t mode) {

	file_type_t file_type = '\0';

	if (S_ISLNK(mode) || S_ISREG(mode) || S_ISDIR(mode)) {
		file_type = FILE_TYPE_REGULAR;
	} else if (S_ISCHR(mode) || S_ISBLK(mode)) {
		file_type = FILE_TYPE_DEVICE;
	} else if (S_ISFIFO(mode)) {
		file_type = FILE_TYPE_PIPE;
	} else if (S_ISSOCK(mode)) {
		file_type = FILE_TYPE_SOCKET;
	} else {
		file_type = FILE_TYPE_OTHER;
	}

	return file_type;

}
/* ================================================================== */



/* ================================================================== */
/**
 * This function is not well named.  It does not directly emit a
 * record, but rather constructs and buffers it for later.  From the
 * caller's viewpoint, however, it is the function for adding a kernel
 * event to the log of them; the buffered events are later flushed to
 * the kernel trace file by the kvmtraced helper thread.
 **/

void 
emit_kernel_record (kernel_event_s* kernel_event)
{

    timestamp_t cycle_timestamp;
    timestamp_t reference_timestamp;
    cputime_t user_time;
    cputime_t system_time;

    if (unlikely(!kt_buffer)) {
	    kt_buffer = (char*)kmalloc(KT_BUFFER_SIZE, GFP_KERNEL);
	    BUG_ON(!kt_buffer);
	    kt_i = 0;
    }

    /*
     * Is kt_i going to far?  If so, sleep (or something).
     */
    if (kt_i >= KT_BUFFER_SIZE - KT_MAX_RECORD_SIZE) {
	    printk(KERN_NOTICE "Buffer needs flushing! Sleeping...\n");
	    __set_current_state(TASK_INTERRUPTIBLE);
	    schedule_kvmtraced();
    }

    /*
     * Construct the record by placing the fields into the buffer one
     * at a time.  Start with three fields that every record,
     * irrespective of type, contains: a tag, a cycle timestamp, and a
     * virtual reference timestamp (that is, number of references
     * performed by this task).
     */
    rdtscll(cycle_timestamp);
    kt_buffer[kt_i++] = kernel_event->tag;
    kt_buffer[kt_i++] = ' ';
    int_to_string(kt_buffer,
		  &kt_i,
		  (unsigned char*)&cycle_timestamp,
		  sizeof(cycle_timestamp));
    kt_buffer[kt_i++] = ' ';
    task_cputime_adjusted(current, &user_time, &system_time);
    reference_timestamp = ((timestamp_t)user_time *
			   (timestamp_t)references_per_jiffy);
    int_to_string(kt_buffer,
		  &kt_i,
		  (unsigned char*)&reference_timestamp,
		  sizeof(reference_timestamp));

    /*
     * The event's filename may not be null terminated (since
     * strncpy() should have been used to copy into it), so force
     * it to be null terminated.
     */
    kernel_event->filename[filename_buffer_size - 1] = '\0';

    /*
     * Depending on the type of kernel event, complete the *
     * formatting of the record.
     */
    kt_buffer[kt_i++] = ' ';
    switch (kernel_event->tag) {

    case TAG_SCHEDULE:
    case TAG_ACCEPT:

	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    break;

    case TAG_EXIT: {

	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&user_time,
			  sizeof(user_time));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&system_time,
			  sizeof(system_time));
	    break;

    }

    case TAG_FORK:

	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->parent_pid),
			  sizeof(kernel_event->parent_pid));
	    break;

    case TAG_EXEC:

	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->inode),
			  sizeof(kernel_event->inode));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->device_ID),
			  sizeof(kernel_event->device_ID));
	    kt_buffer[kt_i++] = ' ';
	    string_to_string(kt_buffer,
			     &kt_i,
			     kernel_event->filename);

	    break;

    case TAG_CONTEXT_ASSIGNMENT:

	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->context),
			  sizeof(kernel_event->context));
	    break;

    case TAG_DUPLICATE_RANGE:

	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->context),
			  sizeof(kernel_event->context));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->duplicate_context),
			  sizeof(kernel_event->duplicate_context));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->address),
			  sizeof(kernel_event->address));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->end_address),
			  sizeof(kernel_event->end_address));
	    break;

    case TAG_MMAP_FILE:

	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->address),
			  sizeof(kernel_event->address));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->length),
			  sizeof(kernel_event->length));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->inode),
			  sizeof(kernel_event->inode));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->device_ID),
			  sizeof(kernel_event->device_ID));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->file_offset),
			  sizeof(kernel_event->file_offset));
	    kt_buffer[kt_i++] = ' ';
	    kt_buffer[kt_i++] = kernel_event->file_type;
	    kt_buffer[kt_i++] = ' ';
	    string_to_string(kt_buffer,
			     &kt_i,
			     kernel_event->filename);
	    break;

    case TAG_MREMAP:

	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->address),
			  sizeof(kernel_event->address));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->length),
			  sizeof(kernel_event->length));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->old_address),
			  sizeof(kernel_event->old_address));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->old_length),
			  sizeof(kernel_event->old_length));
	    kt_buffer[kt_i++] = ' ';
	    break;

    case TAG_MMAP_ANONYMOUS:
    case TAG_MUNMAP:

	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->address),
			  sizeof(kernel_event->address));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->length),
			  sizeof(kernel_event->length));
	    break;

    case TAG_COMPLETE_UNMAP:

	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->context),
			  sizeof(kernel_event->context));
	    break;

    case TAG_SHMAT:

	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->address),
			  sizeof(kernel_event->address));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->length),
			  sizeof(kernel_event->length));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->shm),
			  sizeof(kernel_event->shm));
	    break;

    case TAG_SHM_DESTROY:

	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->shm),
			  sizeof(kernel_event->shm));
	    break;

    case TAG_COW_UNMAP:

	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->address),
			  sizeof(kernel_event->address));
	    break;

    case TAG_FILE_OPEN:

	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->inode),
			  sizeof(kernel_event->inode));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->device_ID),
			  sizeof(kernel_event->device_ID));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->file_offset),
			  sizeof(kernel_event->file_offset));
	    kt_buffer[kt_i++] = ' ';
	    kt_buffer[kt_i++] = kernel_event->file_type;
	    kt_buffer[kt_i++] = ' ';
	    string_to_string(kt_buffer,
			     &kt_i,
			     kernel_event->filename);
	    break;

    case TAG_FILE_CLOSE:

	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->inode),
			  sizeof(kernel_event->inode));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->device_ID),
			  sizeof(kernel_event->device_ID));
	    break;

    case TAG_FILE_READ:
    case TAG_FILE_WRITE:

	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->inode),
			  sizeof(kernel_event->inode));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->device_ID),
			  sizeof(kernel_event->device_ID));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->file_offset),
			  sizeof(kernel_event->file_offset));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->length),
			  sizeof(kernel_event->length));
	    break;

    case TAG_FILE_DELETE:

	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->inode),
			  sizeof(kernel_event->inode));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->device_ID),
			  sizeof(kernel_event->device_ID));
	    break;

    case TAG_FILE_TRUNCATE:

	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->inode),
			  sizeof(kernel_event->inode));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->device_ID),
			  sizeof(kernel_event->device_ID));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->file_offset),
			  sizeof(kernel_event->file_offset));
	    break;

    case TAG_DEBUG:

	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->address),
			  sizeof(kernel_event->address));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->end_address),
			  sizeof(kernel_event->end_address));
	    kt_buffer[kt_i++] = ' ';
	    int_to_string(kt_buffer,
			  &kt_i,
			  (unsigned char*)&(kernel_event->length),
			  sizeof(kernel_event->length));
	    break;

    default:

	    /* Emit to the kernel log. */
	    printk(KERN_ERR "kVMTraced: Unknown kernel record tag %c(%d)\n",
		   kernel_event->tag,
		   (int)kernel_event->tag);

    }

    /* Complete the record with a newline character. */
    kt_buffer[kt_i++] = '\n';

    /*
     * If the buffer is more than half full, then wake up the
     * kvmtraced thread.
     */
    if (kt_i >= KT_BUFFER_SIZE / 2) {
	    schedule_kvmtraced();
    }

}
/* ================================================================== */



/* ================================================================== */
void
sync_kernel_trace (void)
{

    vfs_fsync(kt_filp, 0);

}
/* ================================================================== */



/* ================================================================== */
/*
 * The entry point for the kvmtraced kernel thread.
 * Set the thread to flush its buffer periodically.
 */

int
kvmtraced (void* unused)
{

	/*
	 * Forever check the buffer for flushing (and do so, if
	 * needed).
	 */
	while (1) {

		/*
		 * If the buffer is sufficiently full, then flush
		 * it.
		 */
		if (kt_i + KT_MAX_RECORD_SIZE >= KT_BUFFER_SIZE) {
			flush_kernel_trace();
		}

		/*
		 * Go to sleep.  Time or the emit_kernel_trace() code
		 * may wake up the thread to attempt the next flush.
		 */
		__set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(1000 * HZ);

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

static int __init kvmtraced_init (void)
{

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
