#include "pin.H"

#ifdef TARGET_WINDOWS
#define _CRT_RAND_S
#endif

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#ifndef TARGET_WINDOWS
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#endif

////////////////////////////////////////////////////////////////
// Cross platform abstractions
////////////////////////////////////////////////////////////////

#ifdef TARGET_WINDOWS
#define isWindows 1
#else
#define isWindows 0
#endif

#ifdef TARGET_LINUX
#define isLinux 1
#else
#define isLinux 0
#endif

#ifdef TARGET_MAC
#define isMac 1
#else
#define isMac 0
#endif

#ifdef TARGET_IA32E
#define is64Bit 1
#else
#define is64Bit 0
#endif

#ifdef TARGET_WINDOWS
#define ALLOC_GRAN (64<<10) // In theory, we check GetSystemInfo .dwAllocationGranularity
#else
#define ALLOC_GRAN (8192) // Linux and OS X are fine with >= 1 page.
#endif
#define ALLOC_GRAN_MASK (~(ALLOC_GRAN-1))

#ifdef TARGET_WINDOWS
namespace WINDOWS {
	#include <Windows.h>
	
	static void LastErrorExit(const char *funcName) {
		LPVOID lpMsgBuf;
		LPVOID lpDisplayBuf;
		DWORD dw = GetLastError();
		FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, dw,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)&lpMsgBuf, 0, NULL
		);
		fprintf(stderr, "qira: %s failed with error %d (%s)\n", funcName, dw, lpMsgBuf);
		fflush(stderr);
		LocalFree(lpMsgBuf);
		ExitProcess(dw); 
	}
}
#endif

static inline void _perror_exit(const char *s) {
	int err = errno;
	perror(s);
	exit(err);
}
#define perror_exit(s) _perror_exit("qira: " s)

#ifdef TARGET_WINDOWS
#define atomic_postinc32(x) (InterlockedIncrement((long volatile*)(x))-1)
#else
#define atomic_postinc32(x) __sync_fetch_and_add((x), 1)
#endif

#ifdef TARGET_WINDOWS
#define mkdir(x, y) WINDOWS::CreateDirectoryA((x), NULL)
#endif

#if defined(_MSC_VER) && _MSC_VER < 1900
static int vsnprintf(char *buf, size_t size, const char *fmt, va_list args) {
	int ret = -1;
	if(size != 0)
		ret = vsnprintf_s(buf, size, _TRUNCATE, fmt, args);
	if (ret == -1)
		ret = _vscprintf(fmt, args);
	return ret;
}

static inline int snprintf(char *buf, size_t size, const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	int ret = vsnprintf(buf, size, fmt, args);
	va_end(args);
	return ret;
}
#endif

// #ifndef TARGET_MAC
// #ifdef TARGET_WINDOWS
// static inline uint32_t arc4random() {
// 	unsigned int x;
// 	rand_s(&x);
// 	return x;
// }
// #else
// static uint32_t arc4random() {
// 	static int fd = 0;
// 	if(!fd) fd = open("/dev/urandom", O_RDONLY);
// 	uint32_t x;
// 	read(fd, &x, 4);
// 	return x;
// }
// #endif
// #endif

#ifdef TARGET_WINDOWS
#define MMAPFILE WINDOWS::HANDLE
static MMAPFILE mmap_open(const char *path) {
	WINDOWS::HANDLE handle = WINDOWS::CreateFile(
		path, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
	);
	if(!handle) WINDOWS::LastErrorExit("mmap_open CreateFile");
	return handle;
}
static inline void mmap_close(MMAPFILE handle) {
	WINDOWS::CloseHandle(handle);
}
static void truncate(MMAPFILE handle, size_t size) {
	WINDOWS::LARGE_INTEGER lisaved, lizero, lisize;
	lizero.QuadPart = 0;
	lisize.QuadPart = size;
	WINDOWS::SetFilePointerEx(handle, lizero, &lisaved, FILE_CURRENT);
	WINDOWS::SetFilePointerEx(handle, lisize, NULL, FILE_BEGIN);
	WINDOWS::SetEndOfFile(handle);
	WINDOWS::SetFilePointerEx(handle, lisaved, NULL, FILE_BEGIN);
	//WINDOWS::SetFileValidData(handle, size);
}
static void *mmap_map(MMAPFILE handle, size_t size, size_t offset = 0) {
	WINDOWS::LARGE_INTEGER lisize;
	GetFileSizeEx(handle, &lisize);
	if(lisize.QuadPart < offset+size)
		truncate(handle, offset+size);

	WINDOWS::HANDLE fileMapping = WINDOWS::CreateFileMapping(handle, NULL, PAGE_READWRITE, 0, 0, NULL);
	if(!fileMapping) WINDOWS::LastErrorExit("mmap_map CreateFileMapping");

#ifdef TARGET_IA32E
	size_t high_offset = (offset >> 32) & 0xFFFFFFFFul;
#else
	size_t high_offset = 0;
#endif
	void *ret = WINDOWS::MapViewOfFileEx(fileMapping, FILE_MAP_READ | FILE_MAP_WRITE, high_offset, offset&0xFFFFFFFFul, size, NULL);
	WINDOWS::CloseHandle(fileMapping);
	if(!ret) WINDOWS::LastErrorExit("mmap_map MapViewOfFileEx");
	
	return ret;
}
static inline void mmap_unmap(void *buf, size_t size) {
	if(buf) WINDOWS::UnmapViewOfFile(buf);
}

#else // Linux and OS X
#define MMAPFILE int
static MMAPFILE mmap_open(const char *path) {
	int fd = open(path, O_RDWR|O_CREAT, 0644);
	if(fd == -1) perror_exit("mmap_open open");
	return fd;
}
static inline void mmap_close(MMAPFILE fd) {
	close(fd);
}
static void *mmap_map(MMAPFILE fd, size_t size, size_t offset = 0) {
	//struct stat st;
	//fstat(fd, &st);
	USIZE thesize=0;
	OS_FileSizeFD(fd,&thesize);
	if(static_cast<size_t>(thesize) < offset+size)
		ftruncate(fd, offset+size);

	void *ret = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
	if(ret == MAP_FAILED) perror_exit("mmap_map mmap");

	return ret;
}
static inline void mmap_unmap(void *buf, size_t size) {
	if(buf) munmap(buf, size);
}
#endif

////////////////////////////////////////////////////////////////
// Syscall includes & defines
////////////////////////////////////////////////////////////////

#if defined(TARGET_LINUX)
	#include "strace/syscalls.h"
	#if defined(TARGET_IA32E)
		#define SYS_READ 0
		#include "strace/syscallents_64.h"
	#else
		#define SYS_READ 3
		#include "strace/syscallents_32.h"
	#endif
#elif defined(TARGET_MAC)
	#define SYS_READ 3
	#include "strace/osx_syscalls.h"
#else
	#include "strace/syscalls.h"
	const int MAX_SYSCALL_NUM = 0;
	struct syscall_entry syscalls[1];
#endif

////////////////////////////////////////////////////////////////
// qira trace format
////////////////////////////////////////////////////////////////

#define IS_VALID    0x80000000
#define IS_WRITE    0x40000000
#define IS_MEM      0x20000000
#define IS_START    0x10000000
#define IS_SYSCALL  0x08000000
#define SIZE_MASK   0xFF

struct logstate {
	uint32_t change_count;
	uint32_t changelist_number;
	uint32_t is_filtered;
	uint32_t first_changelist_number;
	uint32_t parent_id;
	uint32_t this_pid;
};

struct change {
	uint64_t address;
	uint64_t data;
	uint32_t changelist_number;
	uint32_t flags;
};

////////////////////////////////////////////////////////////////
// PIN globals
////////////////////////////////////////////////////////////////

static TLS_KEY thread_state_tls_key;
static REG writeea_scratch_reg;
static const ADDRINT WRITEEA_SENTINEL = (sizeof(ADDRINT) > 4) ? (ADDRINT)0xDEADDEADDEADDEADull : (ADDRINT)0xDEADDEADul;
// ^ Don't worry, programs are free to collide with this. It's really just for debug assertions.

// TODO: Something that supports multiple filter ranges, etc.
static ADDRINT filter_ip_low = 0;
static ADDRINT filter_ip_high = (ADDRINT)-1;

////////////////////////////////////////////////////////////////
// pintool arguments
////////////////////////////////////////////////////////////////

static KNOB<string> KnobOutputDir(KNOB_MODE_WRITEONCE, "pintool", "o",
	isWindows ? "./qira_logs" : "/tmp/qira_logs",
	"specify output directory"
);

static KNOB<BOOL> KnobMakeStandaloneTrace(KNOB_MODE_WRITEONCE, "pintool", "standalone",
	KNOB_ONLY_ON_WINDOWS, // Enable by default on windows, since qira doesn't work there yet
	"produce trace package suitable for moving to other systems"
);

// static KNOB<BOOL> KnobSerializeThreads(KNOB_MODE_WRITEONCE, "pintool", "serialize",
// 	"0",
// 	"serialize threads for a more consistent view of time and memory"
// );

////////////////////////////////////////////////////////////////
// qirapin state
////////////////////////////////////////////////////////////////

class Thread_State {
	uint32_t qira_fileid;

	FILE *strace_file;

	MMAPFILE file_handle;
	void *logstate_region;
	void *mapped_region;
	size_t mapped_region_start;
	size_t mapped_region_end;

public:
	static inline Thread_State *get(THREADID tid) {
		return static_cast<Thread_State*>(PIN_GetThreadData(thread_state_tls_key, tid));
	}
	static inline Thread_State *get() {
		return get(PIN_ThreadId());
	}
	
	Thread_State(uint32_t fileid, uint32_t parent, uint32_t chglist) : qira_fileid(fileid) {
		char path[2100];
		int len = snprintf(path, sizeof path, "%s/%u", KnobOutputDir.Value().c_str(), qira_fileid);
		file_handle = mmap_open(path);
		
		mapped_region_start = 0;
		mapped_region_end = ALLOC_GRAN; // Initial size
		mapped_region = mmap_map(file_handle, mapped_region_end - mapped_region_start, mapped_region_start);
		logstate_region = mmap_map(file_handle, sizeof(struct logstate), 0);
		
		snprintf(path+len, sizeof(path) - len, "_strace");
		strace_file = fopen(path, "wb");
		if(!strace_file) perror_exit("fopen");
		
		struct logstate *log = logstate();
		log->change_count = 1;
		log->changelist_number = chglist;
		log->is_filtered = 1;
		log->first_changelist_number = chglist;
		log->parent_id = parent;
		log->this_pid = qira_fileid;
	}

	~Thread_State() {
		mmap_unmap(logstate_region, sizeof(struct logstate));
		mmap_unmap(mapped_region, mapped_region_end - mapped_region_start);
		mmap_close(file_handle);
		fclose(strace_file);
	}

	static inline void tls_destruct(void *tls) { delete static_cast<Thread_State *>(tls); }

	inline struct logstate *logstate() const {
		return static_cast<struct logstate *>(logstate_region);
	}

	// Get a change, shifting (and expanding) the loaded region of the file as necessary
	inline struct change *change(size_t i) {
		size_t target = sizeof(struct change) * (i+1); // +1 because first "change" is actually a header.
		register size_t endtarget = target + sizeof(struct change);
		if(endtarget > mapped_region_end) { // Ran out of space, shift the mapped_region frame forward.
			size_t region_size = mapped_region_end - mapped_region_start;
			mmap_unmap(mapped_region, region_size);

			const register size_t behind = 32*sizeof(struct change); // Overlap the old region a bit. Seems prudent.
			mapped_region_start = target > behind ? target - behind : 0;
			mapped_region_start &= ALLOC_GRAN_MASK;
			region_size = region_size*3/2 + 2*ALLOC_GRAN; // Allocate more space than we did last time.
			region_size &= ALLOC_GRAN_MASK;

			// Clip to maximum 512 MB.
			if(region_size > (512<<20)) region_size = (512<<20);
			if(endtarget > mapped_region_start+region_size) { // Bizarre edge case that won't happen.
				region_size = (endtarget - mapped_region_start + ALLOC_GRAN) & ALLOC_GRAN_MASK;
			}
			mapped_region_end = mapped_region_start + region_size;
			mapped_region = mmap_map(file_handle, region_size, mapped_region_start);
		}
		return reinterpret_cast<struct change *>((char*)mapped_region + target - mapped_region_start);
	}

	// TODO: Maybe need to do something smart to not screw up on forks
	inline int strace_printf(const char *fmt, ...) {
		va_list args;
		va_start(args, fmt);
		int ret = vfprintf(strace_file, fmt, args);
		va_end(args);
		return ret;
	}

	inline void strace_flush() {
		fflush(strace_file);
	}
};

class Process_State {
	PIN_LOCK lock;
	uint32_t main_id; // lol
	volatile uint32_t threads_created;
	volatile uint32_t changelist_number;
	FILE *base_file;

public:
	string *image_folder;

	Process_State() : main_id(0xDEADBEEF), threads_created(0xDEADBEEF), changelist_number(1), base_file(NULL), image_folder(NULL) {
		PIN_InitLock(&lock);
	}

	void init(INT pid) {
		// Called at program start, and also after a fork to update self for a new child.
		// Thread start will be called after this.
		main_id = 0x7FFFFFFF & (pid << 16); // New tracefile format needs to separate out the program from the first thread.
		threads_created = 0;
		
		char path[2100];
		int len = snprintf(path, sizeof path, "%s/%u", KnobOutputDir.Value().c_str(), main_id);
		
		if(KnobMakeStandaloneTrace) {
			if(image_folder) delete image_folder;
			image_folder = new string(path);
			image_folder->append("_images");
			mkdir(image_folder->c_str(), 0755);
		}
		
		snprintf(path+len, sizeof(path) - len, "_base");
		FILE *new_base_file = fopen(path, "wb+");
		if(!new_base_file) perror_exit("fopen");
		if(base_file) {
			long x = ftell(base_file);
			rewind(base_file);
			while(x > 0) {
				// Use `path` as a copy buffer, why not.
				size_t y = fread(path, 1, sizeof path, base_file);
				size_t z = fwrite(path, 1, y, new_base_file);
				ASSERT(y > 0 && z == y, "File IO error while copying base file.");
				x -= y;
			}
			fclose(base_file);
		}
		base_file = new_base_file;
	}

	void fini() {
		fclose(base_file);
	}

#ifndef TARGET_WINDOWS
	void fork_before(THREADID tid) {
		PIN_GetLock(&lock, 0);
		//sync();
		// TODO: Close all files, reopen later
		// I think this is only required for the current tid's data structure.
	}
	void fork_after_parent(THREADID tid) {
		PIN_ReleaseLock(&lock);
	}
	void fork_after_child(THREADID tid, int new_pid) {
		init(new_pid);
		changelist_number -= 1; // hax
		thread_start(tid);
		PIN_ReleaseLock(&lock);
	}
#endif

	void thread_start(THREADID tid) {
		uint32_t t = atomic_postinc32(&threads_created);
		uint32_t qira_fileid = main_id ^ t; // TODO: New trace format needs more (i.e. arbitrary) name bits
		Thread_State *state = new Thread_State(qira_fileid, main_id == qira_fileid ? -1 : main_id, claim_changelist_number());
		PIN_SetThreadData(thread_state_tls_key, static_cast<void*>(state), tid);
	}

	void thread_fini(THREADID tid) {}

	inline int claim_changelist_number() {
		return atomic_postinc32(&changelist_number);
	}

	inline int base_printf(const char *fmt, ...) {
		va_list args;
		va_start(args, fmt);
		int ret = vfprintf(base_file, fmt, args);
		va_end(args);
		return ret;
	}

	inline void base_flush() {
		fflush(base_file);
	}
};

static Process_State process_state;

static inline void add_change(THREADID tid, uint64_t addr, uint64_t data, uint32_t flags) {
	Thread_State *state = Thread_State::get(tid);
	struct logstate *log = state->logstate();
	struct change *c = state->change(log->change_count-1);
	c->address = addr;
	c->data = data;
	c->changelist_number = log->changelist_number;
	c->flags = flags|IS_VALID;
	log->change_count++;
}

static void add_big_change(THREADID tid, uint64_t addr, const void *data, uint32_t flags, size_t size) {
	const UINT64 *v = (const UINT64 *)data;
	while(size >= 8) {
		add_change(tid, addr, *v, flags|64);
		addr += 8; size -= 8; v++;
	}
	if(size) {
		UINT64 x = *v & ~(~(UINT64)0 << size*8);
		add_change(tid, addr, x, flags|(size*8));
	}
}

////////////////////////////////////////////////////////////////
// Memory & register instrumentation functions
////////////////////////////////////////////////////////////////

// TODO: See if merging analysis routines improves perf.

VOID RecordStart(THREADID tid, ADDRINT ip, UINT32 size) {
	Thread_State::get(tid)->logstate()->changelist_number = process_state.claim_changelist_number();
	add_change(tid, ip, size, IS_START);
}

VOID RecordRegRead(THREADID tid, UINT32 regaddr, PIN_REGISTER *value, UINT32 size) {
	add_big_change(tid, regaddr, value->byte, 0, size);
}

VOID RecordRegWrite(THREADID tid, UINT32 regaddr, PIN_REGISTER *value, UINT32 size) {
	add_big_change(tid, regaddr, value->byte, IS_WRITE, size);
}

VOID RecordMemRead(THREADID tid, ADDRINT addr, UINT32 size) {
	UINT64 value[16];
	ASSERT(size <= sizeof(value), "Single instructions can't read this much memory.");
	PIN_SafeCopy(value, (const VOID *)addr, size); // Can assume it worked.
	add_big_change(tid, addr, value, IS_MEM, size);
}

ADDRINT RecordMemWrite1(THREADID tid, ADDRINT addr, ADDRINT oldval) {
	ASSERT(oldval == WRITEEA_SENTINEL, "qirapin scratch register was perturbed from it's sentinel value!");
	return addr;
}
ADDRINT RecordMemWrite2(THREADID tid, ADDRINT addr, UINT32 size) {
	UINT64 value[16];
	ASSERT(size <= sizeof(value), "Single instructions can't write this much memory.");
	PIN_SafeCopy(value, (const VOID *)addr, size); // Can assume it worked.
	add_big_change(tid, addr, value, IS_MEM|IS_WRITE, size);
	return WRITEEA_SENTINEL;
}

VOID RecordSyscall(THREADID tid, ADDRINT num) {
	// Most of syscall recording is in the SyscallEntry and SyscallExit handlers.
	add_change(tid, num, 0, IS_SYSCALL);
}

UINT32 RegToQiraRegAddr(REG r) {
  #if defined(TARGET_IA32E)
		switch(REG_FullRegName(r)) {
			case REG_GAX: return 0;
			case REG_GCX: return 8;
			case REG_GDX: return 16;
			case REG_GBX: return 24;
			case REG_STACK_PTR: return 32;
			case REG_GBP: return 40;
			case REG_GSI: return 48;
			case REG_GDI: return 56;
			case REG_R8:  return 8*8;
			case REG_R9:  return 9*8;
			case REG_R10: return 10*8;
			case REG_R11: return 11*8;
			case REG_R12: return 12*8;
			case REG_R13: return 13*8;
			case REG_R14: return 14*8;
			case REG_R15: return 15*8;
			case REG_INST_PTR: return 16*8;
			default: return 1024;
		}
  #else
		switch(REG_FullRegName(r)) {
			case REG_EAX: return 0;
			case REG_ECX: return 4;
			case REG_EDX: return 8;
			case REG_EBX: return 12;
			case REG_ESP: return 16;
			case REG_EBP: return 20;
			case REG_ESI: return 24;
			case REG_EDI: return 28;
			case REG_EIP: return 32;
			default: return 1024;
		}
  #endif
}

VOID Instruction(INS ins, VOID *v) {
	// TODO: Maybe do Trace/BBL as per MemTrace example. Consider serializing program on BBs
	ADDRINT address = INS_Address(ins);
	
	// TODO: Might want to consider processing non-traced instructions on a BB level.
	const bool filtered = address < filter_ip_low || filter_ip_high <= address;

	if(!filtered) INS_InsertCall(
		ins, IPOINT_BEFORE, (AFUNPTR)RecordStart, IARG_THREAD_ID,
		IARG_INST_PTR,
		IARG_UINT32, (UINT32)INS_Size(ins),
		IARG_CALL_ORDER, CALL_ORDER_FIRST,
		IARG_END
	);

	UINT32 rRegs = INS_MaxNumRRegs(ins);
	UINT32 wRegs = INS_MaxNumWRegs(ins);
	UINT32 memOps = INS_MemoryOperandCount(ins);

	// INS_InsertPredicatedCall to skip inactive CMOVs and REPs.

	if(!filtered) for(UINT32 i = 0; i < rRegs; i++) {
		REG r = INS_RegR(ins, i);
		if(!REG_is_gr(REG_FullRegName(r))) continue;
		INS_InsertPredicatedCall(
			ins, IPOINT_BEFORE, (AFUNPTR)RecordRegRead, IARG_THREAD_ID,
			IARG_UINT32, RegToQiraRegAddr(r),
			IARG_REG_CONST_REFERENCE, r,
			IARG_UINT32, REG_Size(r),
			IARG_END
		);
	}

	if(!filtered) for(UINT32 i = 0; i < wRegs; i++) {
		REG r = INS_RegW(ins, i);
		if(!REG_is_gr(REG_FullRegName(r))) continue;
		if(INS_HasFallThrough(ins)) {
			INS_InsertPredicatedCall(
				ins, IPOINT_AFTER, (AFUNPTR)RecordRegWrite, IARG_THREAD_ID,
				IARG_UINT32, RegToQiraRegAddr(r),
				IARG_REG_CONST_REFERENCE, r,
				IARG_UINT32, REG_Size(r),
				IARG_END
			);
		}
		if(INS_IsBranchOrCall(ins)) {
			INS_InsertPredicatedCall(
				ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)RecordRegWrite, IARG_THREAD_ID,
				IARG_UINT32, RegToQiraRegAddr(r),
				IARG_REG_CONST_REFERENCE, r,
				IARG_UINT32, REG_Size(r),
				IARG_END
			);
		}
	}

	if(INS_Mnemonic(ins) == "XSAVE") {
		// Avoids "Cannot use IARG_MEMORYWRITE_SIZE on non-standard memory access of instruction at 0xfoo: xsave ptr [rsp]"
		// TODO: Bitch at the PIN folks.
		return;
	}
	if(INS_Mnemonic(ins) == "XSAVEC") {
		// Avoids "Cannot use IARG_MEMORYWRITE_SIZE on non-standard memory access of instruction at 0xfoo: xsavec ptr [rsp]"
		// TODO: Bitch at the PIN folks.
		return;
	}

	for(UINT32 i = 0; i < memOps; i++) {
		if(!filtered && INS_MemoryOperandIsRead(ins, i)) {
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead, IARG_THREAD_ID,
				IARG_MEMORYOP_EA, i,
				IARG_MEMORYREAD_SIZE,
				IARG_END
			);
		}

		// Do these even when filtered.
		if(INS_MemoryOperandIsWritten(ins, i)) {
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite1, IARG_THREAD_ID,
				IARG_MEMORYOP_EA, i,
				IARG_REG_VALUE, writeea_scratch_reg,
				IARG_RETURN_REGS, writeea_scratch_reg,
				IARG_END
			);
			if(INS_HasFallThrough(ins)) {
				INS_InsertPredicatedCall(
					ins, IPOINT_AFTER, (AFUNPTR)RecordMemWrite2, IARG_THREAD_ID,
					IARG_REG_VALUE, writeea_scratch_reg,
					IARG_MEMORYWRITE_SIZE,
					IARG_RETURN_REGS, writeea_scratch_reg,
					IARG_END
				);
			}
			if(INS_IsBranchOrCall(ins)) {
				INS_InsertPredicatedCall(
					ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)RecordMemWrite2, IARG_THREAD_ID,
					IARG_REG_VALUE, writeea_scratch_reg,
					IARG_MEMORYWRITE_SIZE,
					IARG_RETURN_REGS, writeea_scratch_reg,
					IARG_END
				);
			}
		}
	}

	// Do this even when filtered.
	if(INS_IsSyscall(ins)) {
		INS_InsertPredicatedCall(
			ins, IPOINT_BEFORE, (AFUNPTR)RecordSyscall, IARG_THREAD_ID,
			IARG_SYSCALL_NUMBER,
			IARG_END
		);
	}
}

////////////////////////////////////////////////////////////////
// strace instrumentation functions
////////////////////////////////////////////////////////////////

// TODO-LATER: Windows can enter a syscall, trigger application-level callbacks, enter more syscalls
// recursivley, and then exit the syscalls. PIN has support for this.

TLS_KEY syscall_tls_key;
struct Syscall_TLS {
	unsigned syscall;
	unsigned nargs;
	ADDRINT arg[SYSCALL_MAXARGS];
};
static inline void syscall_tls_destruct(void *tls) { delete static_cast<Syscall_TLS *>(tls); }

// Return the string with special characters replaced with backslash codes.
string creprstr(const string &s) {
	std::ostringstream stream;
	stream << std::setbase(16) << std::setfill('0');
	for(size_t i = 0; i < s.length(); i++) {
		char c = s[i];
		switch(c) {
			case '\"': stream << "\\\""; break;
			case '\'': stream << "\\\'"; break;
			case '\\': stream << "\\\\"; break;
			case '\t': stream << "\\t"; break;
			case '\n': stream << "\\n"; break;
			case '\r': stream << "\\r"; break;
			default:
				if(32 <= c && c < 127)
					stream << c;
				else
					stream << "\\x" << std::setw(2) << (int)(unsigned char)c << std::setw(0);
				break;
		}
	}
	return stream.str();
}

VOID SyscallEntry(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v) {
	unsigned int sys_nr = PIN_GetSyscallNumber(ctx, std);
	if(isMac && (sys_nr >> 24) == 2) sys_nr &= 0xFFFFFF;
	
	Syscall_TLS *tls = new Syscall_TLS();
	ASSERT(PIN_GetThreadData(syscall_tls_key, tid) == NULL, "Error, SyscallEntry/Exit entered recursively!"); // TODO: This happens on windows.
	PIN_SetThreadData(syscall_tls_key, static_cast<void*>(tls), tid);

	Thread_State *state = Thread_State::get(tid);

	tls->syscall = sys_nr;
	if(sys_nr < MAX_SYSCALL_NUM) {
		tls->nargs = syscalls[sys_nr].nargs;
		state->strace_printf("%u %u %s(", state->logstate()->changelist_number, state->logstate()->this_pid, syscalls[sys_nr].name);
		for(int i = 0; i < syscalls[sys_nr].nargs; i++) {
			if(isMac && i >= 6) {
				// Avoids "REG_SysCallArgReg: 163: Syscall arg 6th should be taken from stack."
				// TODO: Bitch at the PIN folks.
				state->strace_printf(", ...");
				break;
			}
			if(i > 0) state->strace_printf(", ");
			ADDRINT arg = PIN_GetSyscallArgument(ctx, std, i);
			tls->arg[i] = arg;
			switch (syscalls[sys_nr].args[i]) {
				case ARG_STR: {
					char buffer[104];
					memcpy(&buffer[100], "...", 4);
					PIN_SafeCopy((void*)buffer, (void*)arg, 100);
					state->strace_printf("%p=\"%s\"", arg, creprstr(string((char *)buffer)).c_str());
					break;
				}
				case ARG_INT: {
					state->strace_printf("%lu", (long)arg);
					break;
				}
				case ARG_PTR:
				default: {
					state->strace_printf("%p", (void*)arg);
					break;
				}
			}
		}
		state->strace_printf(") = ");
	} else {
		tls->nargs = 6;
		for(int i = 0; i < 6; i++) {
			tls->arg[i] = PIN_GetSyscallArgument(ctx, std, i);
		}
		state->strace_printf("%u %u %lu(%p, %p, %p, %p, %p, %p) = ",
			state->logstate()->changelist_number, state->logstate()->this_pid, sys_nr,
			(void*)tls->arg[0], (void*)tls->arg[1], (void*)tls->arg[2],
			(void*)tls->arg[3], (void*)tls->arg[4], (void*)tls->arg[5]
		);
	}
	state->strace_flush();
}

VOID SyscallExit(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v) {
	Syscall_TLS *tls = static_cast<Syscall_TLS *>(PIN_GetThreadData(syscall_tls_key, tid));
	PIN_SetThreadData(syscall_tls_key, NULL, tid);

	ADDRINT syscall_return = PIN_GetSyscallReturn(ctx, std);
	Thread_State *state = Thread_State::get(tid);
	state->strace_printf("%p\n", (void*)syscall_return);
	state->strace_flush();

#ifdef SYS_READ
	// geohot doesn't approve of this hack, even though he wrote it
	if(tls->syscall == SYS_READ) {
		if(syscall_return > 0) {
			// We're trusting the syscall to have errored if this memory is invalid or something.
			add_big_change(tid, (uint64_t)tls->arg[1], (void*)tls->arg[1], IS_MEM|IS_WRITE, syscall_return);
		}
	}
#endif

	delete tls;
}

////////////////////////////////////////////////////////////////
// Image load recording
////////////////////////////////////////////////////////////////

string urlencode(const string &s) {
	std::ostringstream stream;
	stream << std::setbase(16) << std::setfill('0');
	for(size_t i = 0; i < s.length(); i++) {
		char c = s[i];
		if(('0' <= c && c <= '9') ||
		   ('A' <= c && c <= 'Z') ||
		   ('a' <= c && c <= 'z') ||
		   c == '-' || c =='.' || c == '_' || c == '~'
		) {
			stream << c;
		} else {
			stream << '%' << std::setw(2) << (int)(unsigned char)c << std::setw(0);
		}
	}
	return stream.str();
}

// If standalone trace package is enabled, dump the memory range to the images folder.
// The format of this folder is
//   _images/
//     a%20url%20encoded%20filepath.dll
//     or%20a%20sparsfile%20directory.dll/
//       0000C000
//       DEADBEEF0000
// where the hex-offset-named files represent data at an offset of the sparsefile.
// We need sparsefiles because OS X has non-contigous images, and the whole range of
// address space becomes the "file" (instead of the just object file, like on windows
// and linux).
void dumpimage(const string &name, ADDRINT offset, bool sparse, ADDRINT low, ADDRINT size) {
	// TODO: Throw a warning when a file would be overwritten.
	// I don't *think* that's happening, but if it is that's a problem.
	if(!process_state.image_folder) return; // Image saving is not enabled.
	std::ostringstream stream;
	stream << *process_state.image_folder << "/" << urlencode(name);
	if(sparse) {
		mkdir(stream.str().c_str(), 0755);
		stream << "/" << std::hex << std::setw(8) << std::setfill('0') << offset;
	} else {
		ASSERT(offset == 0, "Can only make non-sparsefile when offset is 0.");
	}
	FILE *file = fopen(stream.str().c_str(), "wb");
	if(!file) perror_exit("fopen");
	fwrite((void*)low, (size_t)size, 1, file);
	fclose(file);
}

VOID ImageLoad(IMG img, VOID *v) {
	static int once = 0;
	if(!once) { // Hack: filter to main binary. Ideally this would be more controllable with tool args but it's fine for now.
		once = 1;
		std::cerr << "qira: filtering to image " << IMG_Name(img) << std::endl;
		filter_ip_low = IMG_LowAddress(img);
		filter_ip_high = IMG_HighAddress(img)+1;
	}

	string imgname = IMG_Name(img);
	UINT32 numRegions = IMG_NumRegions(img);

	// Yes, paths with newlines will break the basefile. No, I don't care.
	if(numRegions == 0) {
		ADDRINT low = IMG_LowAddress(img);
		ADDRINT high = IMG_HighAddress(img)+1;
		process_state.base_printf("%08x-%08x 0 %s\n", (void*)low, (void*)high, imgname.c_str());
		dumpimage(imgname, 0, false, low, high-low);
	} else {
		// TODO: Try to merge regions, which would avoid some (most?) unnecessary sparse files.
		ADDRINT imglow = IMG_LowAddress(img);
		for(UINT32 i = 0; i < numRegions; i++) {
			ADDRINT low = IMG_RegionLowAddress(img, i);
			ADDRINT high = IMG_RegionHighAddress(img, i)+1;
			if(low == 0) continue;
			process_state.base_printf("%08x-%08x %zx %s\n", (void*)low, (void*)high, (size_t)(low - imglow), imgname.c_str());
			dumpimage(imgname, low - imglow, numRegions > 1, low, high-low);
		}
	}
	process_state.base_flush();
}

////////////////////////////////////////////////////////////////
// Setup & stubs
////////////////////////////////////////////////////////////////

VOID Fini(INT32 code, VOID *v) { process_state.fini(); }

VOID ThreadStart(THREADID tid, CONTEXT *ctx, INT32 flags, VOID *v) {
	process_state.thread_start(tid);
	PIN_SetContextReg(ctx, writeea_scratch_reg, WRITEEA_SENTINEL);
}

VOID ThreadFini(THREADID tid, const CONTEXT *ctx, INT32 code, VOID *v) {
	ASSERT(PIN_GetContextReg(ctx, writeea_scratch_reg) == WRITEEA_SENTINEL, "qirapin scratch register ended up with a weird value.");
	process_state.thread_fini(tid);
}

#ifndef TARGET_WINDOWS
VOID ForkBefore      (THREADID tid, const CONTEXT *ctx, VOID *v) { process_state.fork_before(tid); }
VOID ForkAfterParent (THREADID tid, const CONTEXT *ctx, VOID *v) { process_state.fork_after_parent(tid); }
VOID ForkAfterChild  (THREADID tid, const CONTEXT *ctx, VOID *v) {
	syscall_tls_destruct(PIN_GetThreadData(syscall_tls_key, tid));
	PIN_SetThreadData(syscall_tls_key, NULL, tid);
	process_state.fork_after_child(tid, PIN_GetPid());
}
#endif

int main(int argc, char *argv[]) {
	PIN_InitSymbols();
	if(PIN_Init(argc, argv)) {
		std::cerr << "qira pintool" << std::endl;
		std::cerr << std::endl << KNOB_BASE::StringKnobSummary() << std::endl;
		return 2;
	}

	writeea_scratch_reg = PIN_ClaimToolRegister();
	if(!REG_valid(writeea_scratch_reg)) {
		fprintf(stderr, "Failed to claim a scratch register.\n");
		return 1;
	}

	mkdir(KnobOutputDir.Value().c_str(), 0755);

#ifndef TARGET_WINDOWS // Currently broken on windows
	syscall_tls_key = PIN_CreateThreadDataKey(syscall_tls_destruct);
	PIN_AddSyscallEntryFunction(SyscallEntry, 0);
	PIN_AddSyscallExitFunction(SyscallExit, 0);
#endif

	thread_state_tls_key = PIN_CreateThreadDataKey(Thread_State::tls_destruct);
	PIN_AddFiniFunction(Fini, 0);
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

#ifndef TARGET_WINDOWS
	PIN_AddForkFunction(FPOINT_BEFORE, ForkBefore, 0);
	PIN_AddForkFunction(FPOINT_AFTER_IN_PARENT, ForkAfterParent, 0);
	PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, ForkAfterChild, 0);
	// TODO: Look into InstLib follow child for following execves (and their windows equivalent)
#endif

	INS_AddInstrumentFunction(Instruction, 0);
	IMG_AddInstrumentFunction(ImageLoad, 0);

	process_state.init(PIN_GetPid());
	PIN_StartProgram(); // Note that this unwinds the stack!
}
