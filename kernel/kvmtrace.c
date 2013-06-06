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
/* ================================================================== */



/* ================================================================== */
/* DEBUGGING VARIABLES */

int kvmtrace_state = 0;
/* ================================================================== */



/* ================================================================== */
/* TRACE LOGGING DEFINITIONS */

/* The task for kvmtraced. */
static struct task_struct* kvmtraced_task = NULL;

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
	struct file* file;
	int activator_fd;
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
	file:                  NULL,
	activator_fd:          0,
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
/* FORWARD DECLARATIONS */

/* Defined in fs/read_write.c. */
ssize_t vmt_write_record (struct file* file,
			  const char* buffer,
			  size_t count);
/* ================================================================== */



/* ================================================================== */
/* Flush a single buffer.  Return the result of the flush. */

static int
flush_trace_buffer (struct file* trace_file,
		    struct trace_buffer* buffer) {

	int result;

	/* Sanity check. */
	BUG_ON(!buffer->need_to_flush);

	/* Attempt the write operation. */
	result = vmt_write_record(trace_file,
				  buffer->content,
				  buffer->index);

	/* Validate the write operation. */
	if (result == -1) {

		printk(KERN_ERR "VMT: Failed flush of trace buffer\n");
		vmt_corrupt_traces = VMT_FAILED_BUFFER_DUMP;
		return vmt_corrupt_traces;

	} else if (result != buffer->index) {

		printk(KERN_ERR "VMT: Incomplete flush of trace buffer\n");
		printk(KERN_ERR "VMT:   requested = %d, actual = %d\n",
		       buffer->index,
		       result);
		vmt_corrupt_traces = VMT_INCOMPLETE_BUFFER_DUMP;
		return vmt_corrupt_traces;

	}

	/*
	 * To reach this point, the write must have succeeded.  Reset
	 * this buffer and return success.
	 */
	buffer->index = 0;
	buffer->need_to_flush = 0;
	return VMT_SUCCESS;

}
/* ================================================================== */



/* ================================================================== */
/* Flush the kernel trace buffers to a file. */

static int
flush_trace (struct trace* trace) {

	int i;
	static struct semaphore lock;
	static int lock_initialized = 0;

	/* Sanity check. */
	BUG_ON(trace == NULL);
	BUG_ON(trace->buffers == NULL);

	/*
	 * Only one thread should attempt to flush a trace at a time.
	 * The activator and kvmtraced may collide, so we avoid that
	 * with this semaphore.
	 */
	if (!lock_initialized) {
		sema_init(&lock, 1);
		lock_initialized = 1;
	}
	down(&lock);

	/*
	 * Loop through the buffers, staring at the first one that
	 * needs to be flushed, and ending when the current buffer is
	 * reached.
	 */
	for (i = trace->first_unflushed_index;
	     i != trace->current_index;
	     i = (i + 1) % trace->number_buffers) {

		int result;

		/* Grab the next buffer, which must exist. */
		struct trace_buffer* buffer = trace->buffers[i];

		/* Sanity checks on the buffer. */
		BUG_ON(buffer == NULL);
		BUG_ON(buffer == trace->current_buffer);

		/* Attempt to write the contents of this buffer. */
		result = flush_trace_buffer(trace->file, buffer);

		/* If the write failed, give up on tracing. */
		if (result != VMT_SUCCESS) {
			return result;
		}

	}

	/* Advance the index of the first not-yet-flushed buffer. */
	trace->first_unflushed_index = trace->current_index;

	/* Let any other thread continue its attempt to flush. */
	up(&lock);

	return VMT_SUCCESS;

}
/* ================================================================== */



/* ================================================================== */
/* Create the buffer associated with a trace structure. */

static void
create_trace_buffers (struct trace* trace) {

	int i;
	static struct semaphore lock;
	static int lock_initialized = 0;

	/*
	 * Only one thread should proceed through the creation -- all
	 * other threads seeking to use these buffers have to wait.
	 * If, after obtaining the semaphore, the buffers have been
	 * created, then just return since some other thread actually
	 * took care of it.
	 */
	if (!lock_initialized) {
		sema_init(&lock, 1);
		lock_initialized = 1;
	}
	down(&lock);
	if (trace->buffers != NULL) {
		return;
	}

	/*
	 * Attempt to allocate the array of buffer pointers, ensuring
	 * success.
	 */
	trace->buffers =
		(struct trace_buffer**)vmalloc(sizeof(struct trace_buffer*) *
					       trace->number_buffers);
	BUG_ON(trace->buffers == NULL);

	/*
	 * Attempt to allocate each of the required buffers, ensuring
	 * success.  Initialize the allocated buffers.
	 */
	for (i = 0; i < trace->number_buffers; i++) {

		struct trace_buffer* buffer;

		buffer = (struct trace_buffer*)vmalloc(sizeof(struct trace_buffer));
		BUG_ON(buffer == NULL);

		buffer->content =
			(char*)vmalloc(sizeof(char) * trace->buffer_size);
		BUG_ON(buffer->content == NULL);

		buffer->index = 0;
		buffer->need_to_flush = 0;
		trace->buffers[i] = buffer;

	}

	/* Complete the initialization of the buffers. */
	trace->current_index = 0;
	trace->first_unflushed_index = 0;
	trace->current_buffer = trace->buffers[trace->current_index];

	/*
	 * Release the semaphore so that other threads that might be
	 * trying to create these buffers can move forward and
	 * discover that it's already been done.
	 */
	up(&lock);

}
/* ================================================================== */



/* ================================================================== */
/*
 * Mark the current trace buffer as being full and move to the next
 * one.
 */

static void
handle_full_trace_buffer (struct trace* trace) {

	/* Sanity checks. */
	BUG_ON(trace == NULL);
	BUG_ON(trace->buffers == NULL);
	BUG_ON(trace->current_buffer == NULL);

	/*
	 * Mark the current buffer as needing to be flushed, and move
	 * forward to the next buffer.
	 */
	trace->current_buffer->need_to_flush = 1;
	trace->current_index = ((trace->current_index + 1)
				% trace->number_buffers);
	trace->current_buffer = trace->buffers[trace->current_index];

	/*
	 * If we have wrapped around to a buffer that is still waiting
	 * to be flushed, then the buffers are full and traces are
	 * corrupt.  (Strictly speaking, they are about to become
	 * corrupt, but this is close enough.)
	 */
	if (trace->current_buffer->need_to_flush) {

		if (trace == &kernel_trace) {
			printk(KERN_ERR "VMT: Exhausted kernel trace buffer space\n");
		} else {
			printk(KERN_ERR "VMT: Exhausted reference trace buffer space\n");
		}
		vmt_corrupt_traces = 1;

	}

}
/* ================================================================== */



/* ================================================================== */
/* Activate reference tracing output. */

int
activate_kernel_tracing (const char* pathname) {

	int fd;

	/* If tracing is already active, ignore. */
	if (kernel_trace.file != NULL) {
		return VMT_ALREADY_TRUE;
	}

	/*
	 * If the trace buffers are corrupt, then they're unusable.
	 */
	if (vmt_corrupt_traces) {
		return vmt_corrupt_traces;
	}

	/* Attempt to open the output file. */
	fd = sys_open(pathname,
		      O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE,
		      S_IRUSR | S_IWUSR);
	if (fd == -1) {
		return VMT_OPEN_FAILURE;
	}

	/* Grab a direct pointer to the file structure. */
	kernel_trace.file = vmt_fd_lookup(fd);
	if (kernel_trace.file == NULL) {
		return VMT_FD_LOOKUP_FAILURE;
	}

	/* Hold onto the task and file descriptor of the activator. */
	vmt_activator_task = current;
	kernel_trace.activator_fd = fd;

	/* Attempt to flush the kernel trace buffers. */
	return flush_trace(&kernel_trace);

}
/* ================================================================== */



/* ================================================================== */
/* Deactivate kernel tracing output. */

int
deactivate_kernel_tracing (void) {

	int result;

	/* If tracing is already inactive, ignore. */
	if (kernel_trace.file == NULL) {
		return VMT_ALREADY_TRUE;
	}

	/*
	 * If this call is being performed not by the activator task,
	 * then ignore, because the sys_close() call won't work.
	 */
	if (vmt_activator_task != current) {
		return VMT_NON_ACTIVATOR;
	}

	/* Reference tracing must be deactivated first. */
	if (reference_trace.file != NULL) {
		return VMT_REFERENCE_TRACING_ACTIVE;
	}

	/*
	 * Flush the contents of the buffers.  The call to
	 * handle_full_trace_buffer() will mark the current buffer as
	 * full before flushing is performed by flush_trace().
	 */
	handle_full_trace_buffer(&kernel_trace);
	result = flush_trace(&kernel_trace);
	if (result != 0) {
		return result;
	}

	/* Close the file. */
	result = sys_close(kernel_trace.activator_fd);
	if (result == -1) {
		return VMT_CLOSE_FAILURE;
	}

	/*
	 * Reset variables and return success.  Note that the buffers
	 * can continue to fill.
	 */
	kernel_trace.file = NULL;
	kernel_trace.activator_fd = 0;
	vmt_activator_task = NULL;
	return VMT_SUCCESS;

}
/* ================================================================== */



/* ================================================================== */
/* Activate reference tracing output. */

int
activate_reference_tracing (const char* pathname) {

	int fd;

	/* Ensure that the activator made the request. */
	if (vmt_activator_task != current) {
		return VMT_NON_ACTIVATOR;
	}

	/* If tracing is already active, ignore. */
	if (reference_trace.file != NULL) {
		return VMT_ALREADY_TRUE;
	}

	/* Attempt to open the output file. */
	fd = sys_open(pathname,
		      O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE,
		      S_IRUSR | S_IWUSR);
	if (fd == -1) {
		return VMT_OPEN_FAILURE;
	}

	/* Grab a direct pointer to the file structure. */
	reference_trace.file = vmt_fd_lookup(fd);
	if (reference_trace.file == NULL) {
		return VMT_FD_LOOKUP_FAILURE;
	}

	/* Hold onto the file descriptor of the activator. */
	reference_trace.activator_fd = fd;

	/* If the trace buffers do not exist, create them. */
	if (reference_trace.buffers == NULL) {
		create_trace_buffers(&reference_trace);
	}

	/*
	 * Reset the reference trace buffers, ensuring that they are
	 * ready for use.
	 */
	reference_trace.current_index = 0;
	reference_trace.first_unflushed_index = 0;
	BUG_ON(reference_trace.buffers == NULL);
	reference_trace.current_buffer =
		reference_trace.buffers[reference_trace.current_index];
	BUG_ON(reference_trace.current_buffer == NULL);

	return VMT_SUCCESS;

}
/* ================================================================== */



/* ================================================================== */
/* Deactivate reference tracing output. */

int
deactivate_reference_tracing (void) {

	int result;

	/* If tracing is already inactive, ignore. */
	if (reference_trace.file == NULL) {
		return VMT_ALREADY_TRUE;
	}

	/*
	 * If this call is being performed not by the activator task,
	 * then ignore, because the sys_close() call won't work.
	 */
	if (vmt_activator_task != current) {
		return VMT_NON_ACTIVATOR;
	}

	/*
	 * Flush the contents of the buffers.  The call to
	 * handle_full_trace_buffer() will mark the current buffer as
	 * full before flushing is performed by flush_trace().
	 */
	handle_full_trace_buffer(&reference_trace);
	result = flush_trace(&reference_trace);
	if (result != 0) {
		return result;
	}

	/* Close the file. */
	result = sys_close(reference_trace.activator_fd);
	if (result == -1) {
		return VMT_CLOSE_FAILURE;
	}

	/* Reset variables. */
	reference_trace.file = NULL;
	reference_trace.activator_fd = 0;
	return VMT_SUCCESS;

}
/* ================================================================== */



/* ================================================================== */
/*
 * VMT: Convert an unsigned integer into a hexidecimal text
 * representation.  The caller must provide a buffer space and an
 * index into that buffer space, where the index will be returned
 * pointing to the first byte in the buffer beyond what was added by
 * this function.  Note that the caller must also specify the length
 * of the integer, since short, long, and quad-long types can be
 * handled.
 */

static void
int_to_string (char* buffer,
	       int* buffer_index,
	       unsigned char* value,
	       unsigned int value_size) {

	/*
	 * Loop through the bytes of the value.  Assume (for i386)
	 * little-endianness.
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
/* Schedule kvmtraced if possible. */

static void
schedule_kvmtraced (void) {

	if (kvmtraced_task != NULL) {
		wake_up_process(kvmtraced_task);
	}

}
/* ================================================================== */



/* ================================================================== */
/* Emit a single reference record to the reference trace. */

void
emit_reference_record (evms_entry_s* entry) {

	reference_event_s* reference_event;
	int current_referenced;
	int multireferenced;
	int dirty;

	/*
	 * Do nothing if reference tracing is not active or if the
	 * traces have already been somehow corrupted.
	 */
	if ((reference_trace.file == NULL) || (vmt_corrupt_traces)) {
		return;
	}

	/*
	 * If the entry's PTE was not referenced during any of its
	 * time in the EVMS, then it wasn't actually referenced at
	 * all.  (This situations is possible when user-level signal
	 * handlers are used to catch SIGSEGV on user-level protected
	 * pages).  In this case, emit no record at all.
	 */
	if ((!evms_was_0th_segment_referenced(entry)) &&
	    (!pte_young(*entry->ptep))) {
		return;
	}

	/*
	 * Sanity checks: There must be a current trace buffer, and it
	 * should have space for one more record.
	 */
	BUG_ON(reference_trace.current_buffer == NULL);
	BUG_ON(reference_trace.current_buffer->index + REFERENCE_TRACE_MAX_RECORD_SIZE
	       >= reference_trace.buffer_size);

	/*
	 * Grab a pointer to the next space in the trace buffer where
	 * we can place a reference event structure.
	 */
	reference_event = (reference_event_s*)
		&(reference_trace.current_buffer->content
		  [reference_trace.current_buffer->index]);

	/*
	 * Assign the type tag as the first field of the record.  Note
	 * that dirtiness is determined by the PTE's dirty bit, and
	 * that reference-ness is determined by a combination of first
	 * segment and second segment (current) referenced bits.
	 *
	 * Also note that if the PTE was referenced or deleted prior
	 * to this logging, then the referenced and dirty bit will be
	 * preserved within the EVMS entry.
	 */
	if (evms_is_deleted(entry)) {
		current_referenced =
			evms_was_referenced_upon_deletion(entry);
		dirty = evms_was_dirty_upon_deletion(entry);
	} else {
		current_referenced = pte_young(*entry->ptep);
		dirty = pte_dirty(*entry->ptep);
	}
	multireferenced = (current_referenced &&
			   evms_was_0th_segment_referenced(entry));
	reference_event->tag = (multireferenced
				? (dirty
				   ? TAG_MULTIPLE_WRITE
				   : TAG_MULTIPLE_READ)
				: (dirty
				   ? TAG_SINGLE_WRITE
				   : TAG_SINGLE_READ));

	/* Add the cycle timestamp to the record. */
	reference_event->cycle_timestamp = entry->cycle_timestamp;

	/*Add the reference timestamp to the record. */
	reference_event->reference_timestamp = entry->reference_timestamp;

	/* Add the context to the record. */
	reference_event->context_ID = entry->context;

	/* Add the page number to the record. */
	reference_event->virtual_page_number = entry->virtual_page_number;

	/*
	 * Record the incremented index back into the current buffer
	 * structure.
	 */
	reference_trace.current_buffer->index += sizeof(reference_event_s);

	/*
	 * If the current buffer is full, then move onto the next one.
	 */
	if (reference_trace.current_buffer->index + REFERENCE_TRACE_MAX_RECORD_SIZE
	    >= reference_trace.buffer_size) {

		handle_full_trace_buffer(&reference_trace);

		/*
		 * If tracing is active, schedule kvmtraced to flush
		 * the buffers.
		 */
		if (reference_trace.file != NULL) {

			schedule_kvmtraced();

		}
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
	}

	BUG_ON(file_type == '\0');
	return file_type;

}
/* ================================================================== */



/* ================================================================== */
/* Emit a single kernel event record to the kernel trace. */

void
emit_kernel_record (kernel_event_s* kernel_event) {

	timestamp_t cycle_timestamp;
	timestamp_t reference_timestamp;
	char* content;
	int index;

	/* If the traces have already been corrupted, don't bother. */
	if (vmt_corrupt_traces) {
		return;
	}

	/*
	 * If this is the first call to emit a record, then create the
	 * trace buffers.
	 */
	if (kernel_trace.buffers == NULL) {
		create_trace_buffers(&kernel_trace);
	}

	/*
	 * Sanity checks: There must be a current trace buffer, and it
	 * should have space for one more record.
	 */
	BUG_ON(kernel_trace.current_buffer == NULL);
	BUG_ON(kernel_trace.current_buffer->index + KERNEL_TRACE_MAX_RECORD_SIZE
	       >= kernel_trace.buffer_size);

	/*
	 * We don't care about certain kernel events that occur when
	 * reference tracing is not active.
	 */
	if ((reference_trace.file == NULL) &&
	    (kernel_event->tag == TAG_SCHEDULE)) {

		return;

	}

	/* Grab local copies of the content and index. */
	content = kernel_trace.current_buffer->content;
	index = kernel_trace.current_buffer->index;

	/*
	 * Construct the record by placing the fields into the buffer
	 * one at a time.  Start with three fields that every record,
	 * irrespective of type, contains: a tag, a cycle timestamp,
	 * and a virtual reference timestamp (that is, number of
	 * references performed by this task).
	 */
	rdtscll(cycle_timestamp);
	content[index++] = kernel_event->tag;
	content[index++] = ' ';
	int_to_string(content,
		      &index,
		      (unsigned char*)&cycle_timestamp,
		      sizeof(cycle_timestamp));
	content[index++] = ' ';
	reference_timestamp = ((timestamp_t)current->times.tms_utime *
			       (timestamp_t)references_per_tick);
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

		unsigned long int user_time =
			current->times.tms_utime * HZ;
		unsigned long int system_time =
			current->times.tms_stime * HZ;
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
		printk(KERN_ERR "VMT: Unknown kernel record tag %c(%d)\n",
		       kernel_event->tag,
		       (int)kernel_event->tag);

		/* Record that the traces have been corrupted. */
		vmt_corrupt_traces = 1;

	}

	/* Complete the record with a newline character. */
	content[index++] = '\n';

	/*
	 * Record the incremented index back into the current buffer
	 * structure.
	 */
	kernel_trace.current_buffer->index = index;

	/*
	 * If the current buffer is full, then move onto the next one.
	 */
	if (kernel_trace.current_buffer->index + KERNEL_TRACE_MAX_RECORD_SIZE
	    >= kernel_trace.buffer_size) {

		handle_full_trace_buffer(&kernel_trace);

		/*
		 * If tracing is active, schedule kvmtraced to flush
		 * the buffers.
		 */
		if (kernel_trace.file != NULL) {

			schedule_kvmtraced();

		}
	}

}
/* ================================================================== */



/* ================================================================== */
/* Establish a new PTE value.  Taken from mm/memory.c. */

static void
establish_pte (struct vm_area_struct* vma,
	       unsigned long address,
	       pte_t* ptep,
	       pte_t pte) {

	set_pte(ptep, pte);
	flush_tlb_page(vma, address);
	update_mmu_cache(vma, address, pte);

}
/* ================================================================== */



/* ================================================================== */
/* Set up the EVMS. */

void
initialize_evms (void) {

	/* If the EVMS is initialized, there's nothing to do. */
	if (evms_is_initialized) {
		return;
	}

	/* Initialize each entry in each segment. */
	int segment_index;
	for (segment_index = 0;
	     segment_index < EVMS_NUMBER_SEGMENTS;
	     segment_index++) {

		evms_segment_s* segment = evms_segments[segment_index];
		int entry_index;
		for (entry_index = 0;
		     entry_index < segment->size;
		     entry_index++) {

			evms_entry_s* entry =
				&segment->entries[entry_index];
			entry->ptep = NULL;
			entry->flags = 0;
		}
	}

	/*
	 * Determine the approximate number of references per tick
	 * based on the CPU speed.  This number will be used to
	 * approximate reference time.  These values should be large
	 * enough for integer arithmetic to be sufficiently accurate.
	 */
	references_per_tick = (REFERENCES_PER_KILOCYCLE
			       * cpu_khz
			       / HZ);


	evms_is_initialized = 1;

}
/* ================================================================== */



/* ================================================================== */
/* Determine whether the given PTE is already in the EVMS. */

int
is_evms_member (pte_t* ptep) {

	/*
	 * VMT DEBUG: We leave EVMS_DEBUG defined because when it is
	 * not, this condition seems to incorrectly represent when a
	 * particular ptep is a member of the EVMS.  Why?  What is
	 * going on here?  With EVMS_DEBUG defined (and the full
	 * search performed below), everything works just fine.
	 *
	 * IDEA: Take both the result of this expression and of the
	 * search below and assert that they will match, thus finding
	 * the first instance of a disagreement.
	 */
	if (!EVMS_DEBUG) {

		return !(pte_kernel_disabled(*ptep));

	}

	/* Traverse the segments. */
	int segment_index;
	for (segment_index = 0;
	     segment_index < EVMS_NUMBER_SEGMENTS;
	     segment_index++) {

		/* Traverse the current segment. */
		evms_segment_s* segment = evms_segments[segment_index];
		int entry_index;
		for (entry_index = 0;
		     entry_index < segment->size;
		     entry_index++) {
			
			/*
			 * If this entry already points to the given
			 * PTE and is not marked as deleted, then
			 * return `true' immediately.
			 */
			evms_entry_s* entry =
				&segment->entries[entry_index];
			if ((entry->ptep == ptep) &&
			    (!evms_is_deleted(entry))) {

				return 1;

			}
		}

	}

	/* The PTE was not found. */
	return 0;

}
/* ================================================================== */



/* ================================================================== */
/*
 * Find a given PTE in the EVMS and nullify that entry.  This step is
 * performed for PTEs in the EVMS that are about to be eliminated.
 */

void
delete_from_evms (pte_t* ptep, char* caller) {

	int segment_index;

	/* VMT DEBUG */
	unsigned long debug_address = ptep_to_address(ptep);

	/* Search the each segment for the given PTE. */
	for (segment_index = 0;
	     segment_index < EVMS_NUMBER_SEGMENTS;
	     segment_index++) {

		/* Search each entry for the given PTE. */
		evms_segment_s* segment = evms_segments[segment_index];
		int entry_index;
		for (entry_index = 0;
		     entry_index < segment->size;
		     entry_index++) {

			/* Is this the entry? */
			evms_entry_s* entry =
				&segment->entries[entry_index];
			if ((entry->ptep == ptep) &&
			    (!evms_is_deleted(entry))) {

				/*
				 * Mark the entry as deleted, and end
				 * the search.  Note that we preserve
				 * the referenced and dirty bits for
				 * when this entry is evicted and
				 * logged.
				 */
				if (pte_young(*ptep)) {
					evms_set_referenced_upon_deletion(entry);
				} else {
					evms_clear_referenced_upon_deletion(entry);
				}
				if (pte_dirty(*ptep)) {
					evms_set_dirty_upon_deletion(entry);
				} else {
					evms_clear_dirty_upon_deletion(entry);
				}
				evms_set_deleted(entry);
				entry->ptep = NULL;
				return;

			}
		}
	}

	/*
	 * Something has gone wrong if we seek to delete a PTE that is
	 * not in the EVMS.
	 */
	if (EVMS_DEBUG) {
		printk(KERN_ERR "VMT: Funny caller = %s ", caller);
		printk(KERN_ERR "ptep = %lx ", (unsigned long)ptep);
		printk(KERN_ERR "pte = %lx ", pte_val(*ptep));
		printk(KERN_ERR "pid = %x ", current->pid);
		printk(KERN_ERR "vaddr = %lx\n", debug_address);
	}
#if 0
        /* VMT: Hopefully, there aren't too many of these... */
	BUG();
#endif

}
/* ================================================================== */



/* ================================================================== */
/*
 * Provide a pointer to the entry that should be evicted next based on
 * the FIFO replacement policy.
 */

evms_entry_s* evms_FIFO_replace (evms_segment_s* segment) {

	evms_entry_s* return_entry;

	/* Sanity check. */
	BUG_ON(!evms_is_initialized);

	/*
	 * The current index points either to the eviction candidate
	 * or an empty slot.  Use that slot and advance to the next
	 * entry.
	 */
	return_entry = &segment->entries[segment->index];
	segment->index = (segment->index + 1) % segment->size;

	return return_entry;

}
/* ================================================================== */



/* ================================================================== */
/*
 * Provide a pointer to the entry that should be evicted based on the
 * CLOCK replacement policy
 */

evms_entry_s* evms_CLOCK_replace (evms_segment_s* segment) {

	/* Sanity check. */
	BUG_ON(!evms_is_initialized);

	/*
	 * The current index is the clock's hand.  Sweep until we find
	 * an unused entry slot or an entry with a clear reference
	 * bit.
	 */
	evms_entry_s* return_entry = NULL;
	while (return_entry == NULL) {

		evms_entry_s* entry = &segment->entries[segment->index];

		/* Does the entry point to a PTE? */
		if (entry->ptep != NULL) {

			/* It does. Is the PTE's reference bit set? */
			if (pte_young(*entry->ptep)) {

				/* Clear the reference bit. */
				pte_t new_pte = pte_mkold(*entry->ptep);
				establish_pte(entry->vma,
					      entry->virtual_page_number << PAGE_SHIFT,
					      entry->ptep,
					      new_pte);

			} else {

				/*
				 * The reference bit is clear -- evict
				 * this entry.
				 */
				return_entry = entry;

			}

		} else {

			/* The entry is empty.  Use it. */
			return_entry = entry;

		}

		/* Tick the clock hand. */
		segment->index = (segment->index + 1) % segment->size;

	}

	return return_entry;

}
/* ================================================================== */



/* ================================================================== */
/*
 * Insert a given entry into a given segment.  If the segment is full,
 * evict an entry and return it to the caller.
 */

evms_entry_s*
insert_into_segment (evms_segment_s* segment, evms_entry_s* new_entry) {

	evms_entry_s* evicted_entry = NULL;

	BUG_ON(segment == NULL);
	BUG_ON(new_entry == NULL);

	/*
	 * Call on the segment's replacement policy to obtain a space
	 * that can be used to insert the new entry.
	 */
	evicted_entry = segment->replace(segment);

	/* 
	 * Copy the evicted entry into a separate space, outside of
	 * the proper segment entries.
	 */
	segment->evicted_entry = *evicted_entry;

	/* Copy the new entry into the empty space in the segment. */
	*evicted_entry = *new_entry;

	/* Return the evicted entry (if any). */
	evicted_entry = (segment->evicted_entry.ptep == NULL ?
			 NULL :
			 &segment->evicted_entry);
	return evicted_entry;

}
/* ================================================================== */



/* ================================================================== */
/*
 * Add the given PTE to the EVMS, specifically to the 0th segment.
 * Doing so may cause evictions from one segment into the next.
 * If a PTE is evicted from the final segment (and thus the EVMS),
 * return a copy of its entry.
 *
 * Upon insertion, record whether the PTE is dirty, and then clear its
 * dirty bit so that we can record whether it is dirtied during its
 * time in the EVMS.
 */

evms_entry_s*
insert_into_evms (pte_t* ptep,
		  struct vm_area_struct* vma,
		  unsigned long address) {

	int segment_index;
	evms_entry_s* evicted_entry;

	/*
	 * Sanity checks: The mm should exist, and the PTE should be
	 * both non-null and enabled.
	 */
	BUG_ON(current == NULL);
	BUG_ON(current->mm == NULL);
	BUG_ON(ptep == NULL);
	BUG_ON(pte_none(*ptep));
	BUG_ON(pte_disabled(*ptep));

	/* Set up a temporary entry for the new PTE and its info. */
	evms_entry_s new_entry = {
		ptep:                ptep,
		context:             (unsigned long)(current->mm->pgd) >> PAGE_SHIFT,
		vma:                 vma,
		flags:               0,
		cycle_timestamp:     0,
		reference_timestamp: ((timestamp_t)current->times.tms_utime *
				      (timestamp_t)references_per_tick),
		virtual_page_number: address >> PAGE_SHIFT
	};

	/* Assign the cycle timestamp. */
	rdtscll(new_entry.cycle_timestamp);

	/* Record the dirtiness of the PTE upon insertion. */
	if (pte_dirty(*ptep)) {
		evms_set_dirty_upon_insertion(&new_entry);
	} else {
		evms_clear_dirty_upon_insertion(&new_entry);
	}

	/*
	 * Clear the PTE's dirty bit. Note that we do not need to
	 * commit the new PTE settings.  The previous handling of this
	 * PTE will have flushed the TLB entry if needed already, and
	 * the new settings cannot yet have been faulted into the TLB.
	 */
	*ptep = pte_mkclean(*ptep);

	/* Mark entry as not deleted. */
	evms_clear_deleted(&new_entry);

	/*
	 * Insert this PTE into the 0th segment.  That insertion may
	 * cause a cascade of evictions from one segment to the next,
	 * possibly ending with an eviction from the last segment (and
	 * so from the EVMS).
	 *
	 */
	evicted_entry = &new_entry;
	for (segment_index = 0;
	     ((segment_index < EVMS_NUMBER_SEGMENTS) &&
	      (evicted_entry != NULL));
	     segment_index++) {

		evms_segment_s* segment = evms_segments[segment_index];
		BUG_ON(segment == NULL);

		/*
		 * Insert the previous segment's evicted entry into
		 * the current one.
		 */
		evicted_entry =
			insert_into_segment(segment, evicted_entry);

		/*
		 * If this the eviction from the 0th segment and a
		 * valid entry was evicted into the 1st segment, then
		 * hold onto whether this PTE was marked as
		 * referenced.  Then clear it to track re-referencing.
		 */
		if ((segment_index == 0) && (evicted_entry != NULL)) {

			BUG_ON(evicted_entry->ptep == NULL);
			if (ptep_test_and_clear_young(evicted_entry->ptep)) {
				evms_set_0th_segment_referenced(evicted_entry);
			} else {
				evms_clear_0th_segment_referenced(evicted_entry);
			}
			establish_pte(evicted_entry->vma,
				      evicted_entry->virtual_page_number << PAGE_SHIFT,
				      evicted_entry->ptep,
				      *evicted_entry->ptep);

		}
	}

	BUG_ON(!is_evms_member(ptep));

	/*
	 * If there is an entry being evicted from the EVMS, then
	 * disable the PTE and restore its original dirtiness.  Act on
	 * the entry's PTE only if the entry was not deleted.
	 */
	if ((evicted_entry != NULL) &&
	    (!evms_is_deleted(evicted_entry))) {

		pte_t* evicted_ptep;
		pte_t evicted_pte;

		/* Grab the PTE itself. */
		evicted_ptep = evicted_entry->ptep;

		/*
		 * Sanity check: The page must be present and the page
		 * cannot be disabled by the kernel.  If it is
		 * disabled, it must be disabled by the user.
		 */
		BUG_ON(!pte_present(*evicted_ptep));
		BUG_ON(pte_kernel_disabled(*evicted_ptep));
		BUG_ON(pte_disabled(*evicted_ptep) &&
		       !pte_user_disabled(*evicted_ptep));

		/* Disable the PTE. */
		evicted_pte = pte_kernel_disable(*evicted_ptep);

		/*
		 * If the PTE was clean upon insertion into the EVMS,
		 * then its current dirtiness is up-to-date.  If the
		 * PTE was dirty upon insertion, then it is dirty now.
		 */
		if (evms_was_dirty_upon_insertion(evicted_entry)) {
			evicted_pte = pte_mkdirty(evicted_pte);
		}

		/*
		 * If the PTE was not referenced during its time in
		 * the 0th segment, then its current reference bit is
		 * up-to-date.  If it was, then it should be marked as
		 * referenced now.
		 */
		if (evms_was_0th_segment_referenced(evicted_entry)) {
			evicted_pte = pte_mkyoung(evicted_pte);
		}

		/* Commit the new PTE settings. */
		establish_pte(evicted_entry->vma,
			      evicted_entry->virtual_page_number << PAGE_SHIFT,
			      evicted_ptep,
			      evicted_pte);

	}

	/* Return the evicted entry from the final segment (if any). */
	return evicted_entry;

}
/* ================================================================== */



/* ================================================================== */
void
kernel_disable_page_range (struct vm_area_struct* vma,
			   unsigned long start_address,
			   unsigned long end_address) {

	/* Traverse the range, one page at a time. */
	unsigned long address = start_address;
	while (address < end_address) {

		pgd_t *pgd;
		pmd_t *pmd;
		pte_t *ptep;
		pte_t pte;

		/* Try to find the PTE for the current page. */
		pgd = pgd_offset(vma->vm_mm, address);
		if (pgd_none(*pgd) || pgd_bad(*pgd))
			goto loop_end;

		pmd = pmd_offset(pgd, address);
		if (pmd_none(*pmd) || pmd_bad(*pmd))
			goto loop_end;

		ptep = pte_offset(pmd, address);
		if (!ptep)
			goto loop_end;

		/*
		 * We have the PTE.  If it is for a present,
		 * accessible page that is not already in the EVMS,
		 * then disable it.
		 */
		pte = *ptep;
		if (pte_present(pte) &&
		    !pte_kernel_disabled(pte) &&
		    !is_evms_member(ptep)) {

			pte = pte_kernel_disable(pte);
			establish_pte(vma,
				      address,
				      ptep,
				      pte);

		}

	loop_end:

		/* Advance to the next page. */
		address += PAGE_SIZE;

	}

}
/* ================================================================== */



/* ================================================================== */
/* VMT DEBUG */
int
evms_valid (void) {

	int valid;

	if (!EVMS_DEBUG) {
		return 0;
	}

	if (!evms_is_initialized) {
		return 1;
	}

	valid = 1;
	int segment_index;
	for (segment_index = 0;
	     segment_index < EVMS_NUMBER_SEGMENTS;
	     segment_index++) {

		int entry_index;
		evms_segment_s* segment = evms_segments[segment_index];
		for (entry_index = 0;
		     entry_index < segment->size;
		     entry_index++) {

			evms_entry_s* entry =
				&segment->entries[entry_index];
			if ((entry->ptep != NULL) &&
			    (pte_none(*(entry->ptep))) &&
			    (!evms_is_deleted(entry))) {

				valid = 0;
				printk(KERN_ERR "VMT: Null PTE! ");
				printk(KERN_ERR "ptep = %lx ",
				       (unsigned long)entry->ptep);
				printk(KERN_ERR "vpn  = %lx\n",
				       (unsigned long)entry->virtual_page_number);

			}
		}
	}


	return valid;

}
/* ================================================================== */



/* ================================================================== */
/* Flush a particular trace and check its result */

static void
kvmtrace_flush_trace (struct trace* trace) {

	if (trace->file != NULL) {

		int result = flush_trace(trace);
		if (result != VMT_SUCCESS) {

			printk(KERN_ERR "VMT: Failed %s trace flush\n",
			       trace->name);

		}
	}
}
/* ================================================================== */



/* ================================================================== */
/*
 * The entry point for the kvmtraced kernel thread.
 *
 * DEBUG: Emit *something*.
 */

int
kvmtraced (void* unused) {

	BUG_ON(kvmtraced_task != NULL);

	

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

	printk(KERN_INFO "Starting kvmtraced\n");
	kvmtraced_thread = kthread_run(kvmtraced,
				       &err,
				       "kvmtraced");

	if (err) {
		printk(KERN_ERR "kvmtraced: unable to create thread %i\n", err);
		return err;
	}

	printk(KERN_INFO "kvmtraced: initialized\n");
	return 0;

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
