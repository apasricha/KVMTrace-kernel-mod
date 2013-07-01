/* kVMTrace-modified file */

#ifndef _GENERIC_KVMTRACE_H
#define _GENERIC_KVMTRACE_H

/**
 * Determine whether this is 32- or 64-bit.
 */
#if defined KVMTRACE_32_BIT
typedef kvmt_word_size_t uint32_t;
#else
typedef kvmt_word_size_t uint64_t;
#endif

/**
 * Below are types and structures used for recording kernel and
 * reference events.
 */
typedef uint64_t timestamp_t;
typedef kvmt_word_size_t page_number_t;

/* Types used within the structure. */
typedef char tag_t;
typedef kvmt_word_size_t virtual_address_t;
typedef uint32_t context_ID_t;
typedef uint16_t process_ID_t;
typedef uint32_t inode_ID_t;
typedef uint32_t device_ID_t;
typedef uint32_t shm_ID_t;
typedef uint64_t offset_t;
typedef uint64_t file_offset_t;
typedef char file_type_t;

/* The length of the buffer used to store filenames. */
#define filename_buffer_size 64

/*
 * The type of a structure into which information about kernel events
 * can be recorded.
 */
typedef struct kernel_event_struct {

	tag_t tag;
	process_ID_t pid;
	process_ID_t parent_pid;
	context_ID_t context;
	context_ID_t duplicate_context;
	virtual_address_t address;
	virtual_address_t end_address;
	virtual_address_t old_address;
	offset_t length;
	offset_t old_length;
	inode_ID_t inode;
	device_ID_t major_device;
	device_ID_t minor_device;
	file_offset_t file_offset;
	file_type_t file_type;
	shm_ID_t shm;
	char filename[filename_buffer_size];

} kernel_event_s;

/*
 * The one instance of this structure which will be used everywhere,
 * but is declared in kernel/kvmtrace.c.
 */
extern kernel_event_s kernel_event;

/*
 * Functions that emit kernel events to the appropriate trace.
 */
void emit_kernel_record (kernel_event_s* kernel_event);

/*
 * A function useful for copying the filename used during some kernel
 * events.
 */
void string_to_string (char* buffer,
		       int* buffer_index,
		       char* source);

/*
 * The flag bit for indicating that a given do_munmap() call should
 * not be logged by kVMTrace.  This bit is set within the address
 * passed to do_munmap(), where that bit should be one of the
 * lower-order bits that must be clear anywhere to ensure page
 * alignment.
 */
#define VMT_DO_NOT_LOG 0x1

/* Valid record tags. */
#define TAG_SINGLE_READ             'r'
#define TAG_MULTIPLE_READ           'R'
#define TAG_SINGLE_WRITE            'w'
#define TAG_MULTIPLE_WRITE          'W'
#define TAG_SCHEDULE                'S'
#define TAG_FORK                    'F'
#define TAG_EXEC                    'X'
#define TAG_EXIT                    'T'
#define TAG_CONTEXT_ASSIGNMENT      'A'
#define TAG_DUPLICATE_RANGE         'D'
#define TAG_MMAP_FILE               'M'
#define TAG_MMAP_ANONYMOUS          'm'
#define TAG_MREMAP                  '@'
#define TAG_MUNMAP                  'U'
#define TAG_COMPLETE_UNMAP          'u'
#define TAG_COW_UNMAP               'C'
#define TAG_SHMAT                   's'
#define TAG_SHM_DESTROY             '/'
#define TAG_FILE_OPEN               '('
#define TAG_FILE_CLOSE              ')'
#define TAG_FILE_READ               '<'
#define TAG_FILE_WRITE              '>'
#define TAG_FILE_DELETE             '-'
#define TAG_FILE_TRUNCATE           't'
#define TAG_ACCEPT                  'a'
#define TAG_INVALID                 '!'
#define TAG_END_OF_TRACE            'e'

#define TAG_DEBUG                   '&'

/* Valid file types. */
#define FILE_TYPE_REGULAR           'f'
#define FILE_TYPE_PIPE              'p'
#define FILE_TYPE_DEVICE            'd'
#define FILE_TYPE_SOCKET            's'

/* VMT DEBUG */
extern int kvmtrace_state;

#endif /* _GENERIC_KVMTRACE_H */

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
