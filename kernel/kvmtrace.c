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

#include <asm/msr.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/kvmtrace.h>
#include <linux/syscalls.h>
#include <stdint.h>
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
struct file* kernel_trace_filp = NULL;

/*
 * The length of the text buffer into which the kernel record is
 * composed.
 */
#define RECORD_BUFFER_SIZE 128
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
	       unsigned int value_size) {

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
		  char* source) {

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
open_kernel_trace (void) {

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
void
close_kernel_trace (void) {

    filp_close(kernel_trace_filp, NULL);

}
/* ================================================================== */



/* ================================================================== */
void 
emit_kernel_record (kernel_event_s* kernel_event) {

    mm_segment_t old_fs;
    int ret;
    loff_t pos;

    timestamp_t cycle_timestamp;
    timestamp_t reference_timestamp;
    char content[RECORD_BUFFER_SIZE];
    int index = 0;
    cputime_t user_time;
    cputime_t system_time;

    /*
     * If this is the first call to emit a record, then open the
     * output file.  If the open fails, return without emitting, since
     * the system may not yet be ready to open the trace file.  [SFHK:
     * Later, this function should only buffer the event so that no
     * output to the trace file is lost to early events that precede
     * file system mounting.]
     */
    if (kernel_trace_filp == NULL) {
	    open_kernel_trace();
	    if (IS_ERR(kernel_trace_filp)) {
		    printk(KERN_NOTICE "kvmtraced: Failed open, skipping emit.\n");
		    kernel_trace_filp = NULL;
		    return;
	    }
    }
    pos = kernel_trace_filp->f_pos;

    /*
     * Construct the record by placing the fields into the buffer one
     * at a time.  Start with three fields that every record,
     * irrespective of type, contains: a tag, a cycle timestamp, and a
     * virtual reference timestamp (that is, number of references
     * performed by this task).
     */
    rdtscll(cycle_timestamp);
    content[index++] = kernel_event->tag;
    content[index++] = ' ';
    int_to_string(content,
		  &index,
		  (unsigned char*)&cycle_timestamp,
		  sizeof(cycle_timestamp));
    content[index++] = ' ';
    task_cputime_adjusted(current, &user_time, &system_time);
    reference_timestamp = ((timestamp_t)user_time *
			   (timestamp_t)references_per_jiffy);
    int_to_string(content,
		  &index,
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
    content[index++] = ' ';
    switch (kernel_event->tag) {

    case TAG_SCHEDULE:
    case TAG_ACCEPT:

	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    break;

    case TAG_EXIT: {

	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&user_time,
			  sizeof(user_time));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&system_time,
			  sizeof(system_time));
	    break;

    }

    case TAG_FORK:

	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->parent_pid),
			  sizeof(kernel_event->parent_pid));
	    break;

    case TAG_EXEC:

	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->inode),
			  sizeof(kernel_event->inode));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->major_device),
			  sizeof(kernel_event->major_device));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->minor_device),
			  sizeof(kernel_event->minor_device));
	    content[index++] = ' ';
	    string_to_string(content,
			     &index,
			     kernel_event->filename);

	    break;

    case TAG_CONTEXT_ASSIGNMENT:

	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->context),
			  sizeof(kernel_event->context));
	    break;

    case TAG_DUPLICATE_RANGE:

	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->context),
			  sizeof(kernel_event->context));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->duplicate_context),
			  sizeof(kernel_event->duplicate_context));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->address),
			  sizeof(kernel_event->address));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->end_address),
			  sizeof(kernel_event->end_address));
	    break;

    case TAG_MMAP_FILE:

	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->address),
			  sizeof(kernel_event->address));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->length),
			  sizeof(kernel_event->length));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->inode),
			  sizeof(kernel_event->inode));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->major_device),
			  sizeof(kernel_event->major_device));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->minor_device),
			  sizeof(kernel_event->minor_device));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->file_offset),
			  sizeof(kernel_event->file_offset));
	    content[index++] = ' ';
	    content[index++] = kernel_event->file_type;
	    content[index++] = ' ';
	    string_to_string(content,
			     &index,
			     kernel_event->filename);
	    break;

    case TAG_MREMAP:

	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->address),
			  sizeof(kernel_event->address));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->length),
			  sizeof(kernel_event->length));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->old_address),
			  sizeof(kernel_event->old_address));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->old_length),
			  sizeof(kernel_event->old_length));
	    content[index++] = ' ';
	    break;

    case TAG_MMAP_ANONYMOUS:
    case TAG_MUNMAP:

	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->address),
			  sizeof(kernel_event->address));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->length),
			  sizeof(kernel_event->length));
	    break;

    case TAG_COMPLETE_UNMAP:

	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->context),
			  sizeof(kernel_event->context));
	    break;

    case TAG_SHMAT:

	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->address),
			  sizeof(kernel_event->address));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->length),
			  sizeof(kernel_event->length));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->shm),
			  sizeof(kernel_event->shm));
	    break;

    case TAG_SHM_DESTROY:

	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->shm),
			  sizeof(kernel_event->shm));
	    break;

    case TAG_COW_UNMAP:

	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->address),
			  sizeof(kernel_event->address));
	    break;

    case TAG_FILE_OPEN:

	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->inode),
			  sizeof(kernel_event->inode));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->major_device),
			  sizeof(kernel_event->major_device));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->minor_device),
			  sizeof(kernel_event->minor_device));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->file_offset),
			  sizeof(kernel_event->file_offset));
	    content[index++] = ' ';
	    content[index++] = kernel_event->file_type;
	    content[index++] = ' ';
	    string_to_string(content,
			     &index,
			     kernel_event->filename);
	    break;

    case TAG_FILE_CLOSE:

	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->inode),
			  sizeof(kernel_event->inode));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->major_device),
			  sizeof(kernel_event->major_device));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->minor_device),
			  sizeof(kernel_event->minor_device));
	    break;

    case TAG_FILE_READ:
    case TAG_FILE_WRITE:

	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->inode),
			  sizeof(kernel_event->inode));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->major_device),
			  sizeof(kernel_event->major_device));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->minor_device),
			  sizeof(kernel_event->minor_device));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->file_offset),
			  sizeof(kernel_event->file_offset));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->length),
			  sizeof(kernel_event->length));
	    break;

    case TAG_FILE_DELETE:

	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->inode),
			  sizeof(kernel_event->inode));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->major_device),
			  sizeof(kernel_event->major_device));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->minor_device),
			  sizeof(kernel_event->minor_device));
	    break;

    case TAG_FILE_TRUNCATE:

	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->inode),
			  sizeof(kernel_event->inode));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->major_device),
			  sizeof(kernel_event->major_device));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->minor_device),
			  sizeof(kernel_event->minor_device));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->file_offset),
			  sizeof(kernel_event->file_offset));
	    break;

    case TAG_DEBUG:

	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->pid),
			  sizeof(kernel_event->pid));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->address),
			  sizeof(kernel_event->address));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
			  (unsigned char*)&(kernel_event->end_address),
			  sizeof(kernel_event->end_address));
	    content[index++] = ' ';
	    int_to_string(content,
			  &index,
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
    content[index++] = '\n';

    /*
     * For now, write the record immediately.  Later, a buffer that,
     * when full enough, is flushed by periodic scheduling of
     * kvmtraced.
     */
    old_fs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(kernel_trace_filp, content, index, &pos);
    if (ret != 0) {
	    printk(KERN_ERR "kvmtraced(): Failed emit_kernel_trace()");
    }

    set_fs(old_fs);

}
/* ================================================================== */



/* ================================================================== */
void
sync_kernel_trace (void) {

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

	/* Forever flush the buffer. */
	while (1) {

		/* A fake record. */
		kernel_event.tag = TAG_SCHEDULE;
		kernel_event.pid = 0x123;
		emit_kernel_record(&kernel_event);

		printk(KERN_NOTICE "kvmtraced: Emit attempted, sleeping...\n");
		__set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(10 * HZ);

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
