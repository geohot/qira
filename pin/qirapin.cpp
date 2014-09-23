#ifdef TARGET_WINDOWS
#define _CRT_RAND_S
#endif

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string.h>

#ifndef TARGET_WINDOWS
#include <fcntl.h>
#include <unistd.h>
#endif

#include "pin.H"

#ifdef TARGET_WINDOWS
namespace WINDOWS {
	#include <Windows.h>
	
	void LastErrorExit(char *funcName) {
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
		printf("%s failed with error %d (%s)\n", funcName, dw, lpMsgBuf);
		LocalFree(lpMsgBuf);
		ExitProcess(dw); 
	}
}
#endif

#ifndef TARGET_WINDOWS
#define InterlockedIncrement(x) __sync_add_and_fetch((x), 1)
#endif

#ifdef TARGET_LINUX
#include <stdio_ext.h>
#define fpurge __fpurge
#endif

#ifdef TARGET_WINDOWS
#define fpurge(x) ((void)(x)) // Windows doesn't fork.
#define mkdir(x, y) WINDOWS::CreateDirectoryA((x), NULL)
#else
#include <sys/stat.h>
#endif

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
#include "strace/osx_syscalls.h"
#endif

#define IS_VALID    0x80000000
#define IS_WRITE    0x40000000
#define IS_MEM      0x20000000
#define IS_START    0x10000000
#define IS_SYSCALL  0x08000000
#define SIZE_MASK   0xFF

static struct logstate {
	uint32_t change_count;
	uint32_t changelist_number;
	uint32_t is_filtered;
	uint32_t first_changelist_number;
	uint32_t parent_id;
	uint32_t this_pid;
} *logstate = NULL;

static struct change {
	uint64_t address;
	uint64_t data;
	uint32_t changelist_number;
	uint32_t flags;
} *change = NULL;

size_t change_length = 0;

KNOB<string> KnobOutputDir(KNOB_MODE_WRITEONCE, "pintool", "o",
	#ifdef TARGET_WINDOWS
	".",
	#else
	"/tmp/qira_logs",
	#endif
	"specify output directory"
);

#ifdef TARGET_MAC
	BOOL KnobMakeStandaloneTrace = false; // TODO: IMG_StartAddress is broken on OS X; returns an area of all zero bytes.
#else
KNOB<BOOL> KnobMakeStandaloneTrace(KNOB_MODE_WRITEONCE, "pintool", "standalone",
	#ifdef TARGET_WINDOWS
	"1", // Enable by default on windows, since qira doesn't work there yet
	#else
	"0",
	#endif
	"produce trace files suitable for moving to other systems.");
#endif

#ifdef TARGET_WINDOWS
#define TRACEFILE_TYPE WINDOWS::HANDLE
#define OPEN_TRACEFILE(fn) WINDOWS::CreateFile((fn), GENERIC_READ|GENERIC_WRITE, \
	FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
#define CLOSE_TRACEFILE(x) WINDOWS::CloseHandle((x))
static inline void MMAP_TRACEFILE(WINDOWS::HANDLE handle, size_t size) {
	if (change != NULL) WINDOWS::UnmapViewOfFile(change);
	WINDOWS::LARGE_INTEGER lisaved;
	WINDOWS::LARGE_INTEGER lizero; lizero.QuadPart = 0;
	WINDOWS::LARGE_INTEGER lisize; lisize.QuadPart = size;
	WINDOWS::SetFilePointerEx(handle, lizero, &lisaved, FILE_CURRENT);
	WINDOWS::SetFilePointerEx(handle, lisize, NULL, FILE_BEGIN);
	WINDOWS::SetEndOfFile(handle);
	WINDOWS::SetFilePointerEx(handle, lisaved, NULL, FILE_BEGIN);
	//WINDOWS::SetFileValidData(handle, size);
	WINDOWS::HANDLE fileMapping = WINDOWS::CreateFileMapping(handle, NULL, PAGE_READWRITE, 0, 0, NULL);
	if(!fileMapping) WINDOWS::LastErrorExit("CreateFileMapping");
	change = (struct change *)WINDOWS::MapViewOfFileEx(fileMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, size, NULL);
	if(!change) WINDOWS::LastErrorExit("MapViewOfFileEx");
	change_length = size;
	logstate = (struct logstate*)change;
}
#else
#include <sys/types.h>
#include <sys/mman.h>
#define TRACEFILE_TYPE int
#define OPEN_TRACEFILE(fn) open((fn), O_RDWR|O_CREAT, 0644)
#define CLOSE_TRACEFILE(x) close((x))
static inline void MMAP_TRACEFILE(int x, size_t size) {
	if (change != NULL) munmap(change, change_length);
	ftruncate(x, size);
	change = (struct change*)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, x, 0);
	change_length = size;
	logstate = (struct logstate*)change;
}
#endif


#ifdef TARGET_WINDOWS
static inline uint32_t really_random() {
	unsigned int x;
	rand_s(&x);
	return x;
}
#elif TARGET_MAC
static inline uint32_t really_random() {
	return arc4random();
}
#else
static uint32_t really_random() {
	static int fd = 0;
	if(!fd) fd = open("/dev/urandom", O_RDONLY);
	uint32_t x;
	read(fd, &x, 4);
	return x;
}
#endif

TRACEFILE_TYPE trace_file = 0;
FILE *strace_file = NULL;
FILE *base_file = NULL;
string *image_folder = NULL;
uint32_t file_id = 0;

void new_trace_files(bool isfork = false) {
	static uint32_t start_time = 0;
	if(!start_time) start_time = time(NULL);

	char pathbase[1024];
	char path[1024];
	file_id = PIN_GetPid()<<16;
	file_id |= ((time(NULL)-start_time)<<8)&0xff;
	file_id |= really_random()&0xff;
	sprintf(pathbase, "%s/%u", KnobOutputDir.Value().c_str(), file_id);

	mkdir(KnobOutputDir.Value().c_str(), 0755);
	
	if(trace_file) CLOSE_TRACEFILE(trace_file);
	trace_file = OPEN_TRACEFILE(pathbase);
	ASSERT(trace_file, "Failed to open trace output.");
	MMAP_TRACEFILE(trace_file, sizeof(struct logstate));
	
	if(strace_file) fpurge(strace_file), fclose(strace_file);
	sprintf(path, "%s_strace", pathbase);
	strace_file = fopen(path, "wb");
	ASSERT(strace_file, "Failed to open strace output.");
	
	if(base_file) fpurge(base_file), fclose(base_file);
	if(isfork) {
		// TODO: copy file. requires moving base file to memory, not just as FILE
		base_file = NULL;
	} else {
		sprintf(path, "%s_base", pathbase);
		base_file = fopen(path, "wb");
		ASSERT(base_file, "Failed to open base output.");
	}

	if(KnobMakeStandaloneTrace) {
		image_folder = new string(pathbase);
		image_folder->append("_images/");
		mkdir(image_folder->c_str(), 0755);
	}
}

static void add_change(uint64_t addr, uint64_t data, uint32_t flags) {
	int cn = logstate->change_count;
	if (change_length < (cn+1) * sizeof(struct change)) {
		MMAP_TRACEFILE(trace_file, change_length*2);
	}
	change[cn].address = addr;
	change[cn].data = data;
	change[cn].changelist_number = logstate->changelist_number;
	change[cn].flags = flags|IS_VALID;
	logstate->change_count++;
}

static void add_big_change(uint64_t addr, const void *data, uint32_t flags, size_t size) {
	const UINT64 *v = (const UINT64 *)data;
	while(size >= 8) {
		add_change(addr, *v, flags|64);
		addr += 8; size -= 8; v++;
	}
	if(size) {
		UINT64 x = *v & ~(~(UINT64)0 << size*8);
		add_change(addr, x, flags|(size*8));
	}
}

static REG writeea_scratch_reg;

static ADDRINT filter_ip_low;
static ADDRINT filter_ip_high;

////////////////////////////////////////////////////////////////
// Memory & register instrumentation functions
////////////////////////////////////////////////////////////////

// TODO: See if merging analysis routines improves perf.

VOID RecordStart(ADDRINT ip, UINT32 size) {
	logstate->changelist_number++;
	add_change(ip, size, IS_START);
}

VOID RecordRegRead(UINT32 regaddr, PIN_REGISTER *value, UINT32 size) {
	add_big_change(regaddr, value->byte, 0, size);
}

VOID RecordRegWrite(UINT32 regaddr, PIN_REGISTER *value, UINT32 size) {
	add_big_change(regaddr, value->byte, IS_WRITE, size);
}

VOID RecordMemRead(ADDRINT addr, UINT32 size) {
	UINT64 value[16];
	ASSERT(size <= sizeof(value), "wow");
	PIN_SafeCopy(value, (const VOID *)addr, size); // Can assume it worked.
	add_big_change(addr, value, IS_MEM, size);
}

ADDRINT RecordMemWrite1(ADDRINT addr, ADDRINT oldval) {
	ASSERT(oldval == 0, "This is why you can't have nice things.");
	return addr;
}
ADDRINT RecordMemWrite2(ADDRINT addr, UINT32 size) {
	UINT64 value[16];
	if (size > sizeof(value)) {
		// dangerous address access!
		add_big_change(addr, value, IS_MEM|IS_WRITE, size);
	} else {
		ASSERT(size <= sizeof(value), "wow");
		PIN_SafeCopy(value, (const VOID *)addr, size); // Can assume it worked.
		add_big_change(addr, value, IS_MEM|IS_WRITE, size);
	}
	return 0;
}

VOID RecordSyscall(ADDRINT num) {
	add_change(num, 0, IS_SYSCALL);
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
	// TODO: Do Trace/BBL as per MemTrace example, and lock per BB to support threads.

	ADDRINT address = INS_Address(ins);
	if(address < filter_ip_low || filter_ip_high <= address) return;

	INS_InsertCall(
		ins, IPOINT_BEFORE, (AFUNPTR)RecordStart,
		IARG_INST_PTR,
		IARG_UINT32, (UINT32)INS_Size(ins),
		IARG_CALL_ORDER, CALL_ORDER_FIRST,
		IARG_END
	);

	UINT32 rRegs = INS_MaxNumRRegs(ins);
	UINT32 wRegs = INS_MaxNumWRegs(ins);
	UINT32 memOps = INS_MemoryOperandCount(ins);

	// INS_InsertPredicatedCall to skip inactive CMOVs and REPs.

	for(UINT32 i = 0; i < rRegs; i++) {
		REG r = INS_RegR(ins, i);
		if(!REG_is_gr(REG_FullRegName(r))) continue;
		INS_InsertPredicatedCall(
			ins, IPOINT_BEFORE, (AFUNPTR)RecordRegRead,
			IARG_UINT32, RegToQiraRegAddr(r),
			IARG_REG_CONST_REFERENCE, r,
			IARG_UINT32, REG_Size(r),
			IARG_END
		);
	}

	for(UINT32 i = 0; i < wRegs; i++) {
		REG r = INS_RegW(ins, i);
		if(!REG_is_gr(REG_FullRegName(r))) continue;
		if(INS_HasFallThrough(ins)) {
			INS_InsertPredicatedCall(
				ins, IPOINT_AFTER, (AFUNPTR)RecordRegWrite,
				IARG_UINT32, RegToQiraRegAddr(r),
				IARG_REG_CONST_REFERENCE, r,
				IARG_UINT32, REG_Size(r),
				IARG_END
			);
		}
		if(INS_IsBranchOrCall(ins)) {
			INS_InsertPredicatedCall(
				ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)RecordRegWrite,
				IARG_UINT32, RegToQiraRegAddr(r),
				IARG_REG_CONST_REFERENCE, r,
				IARG_UINT32, REG_Size(r),
				IARG_END
			);
		}
	}

	for(UINT32 i = 0; i < memOps; i++) {
		if(INS_MemoryOperandIsRead(ins, i)) {
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
				IARG_MEMORYOP_EA, i,
				IARG_MEMORYREAD_SIZE,
				IARG_END
			);
		}

		if(INS_MemoryOperandIsWritten(ins, i)) {
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite1,
				IARG_MEMORYOP_EA, i,
				IARG_REG_VALUE, writeea_scratch_reg,
				IARG_RETURN_REGS, writeea_scratch_reg,
				IARG_END
			);
			if(INS_HasFallThrough(ins)) {
				INS_InsertPredicatedCall(
					ins, IPOINT_AFTER, (AFUNPTR)RecordMemWrite2,
					IARG_REG_VALUE, writeea_scratch_reg,
					IARG_MEMORYWRITE_SIZE,
					IARG_RETURN_REGS, writeea_scratch_reg,
					IARG_END
				);
			}
			if(INS_IsBranchOrCall(ins)) {
				INS_InsertPredicatedCall(
					ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)RecordMemWrite2,
					IARG_REG_VALUE, writeea_scratch_reg,
					IARG_MEMORYWRITE_SIZE,
					IARG_RETURN_REGS, writeea_scratch_reg,
					IARG_END
				);
			}
		}
	}

	if(INS_IsSyscall(ins)) {
		INS_InsertPredicatedCall(
			ins, IPOINT_BEFORE, (AFUNPTR)RecordSyscall,
			IARG_SYSCALL_NUMBER,
			IARG_END
		);
	}
}

////////////////////////////////////////////////////////////////
// strace instrumentation functions
////////////////////////////////////////////////////////////////

int sys_nr;
ADDRINT arg1;

VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
  #if defined(TARGET_LINUX) || defined(TARGET_MAC)
    sys_nr = (int)PIN_GetSyscallNumber(ctxt, std);
    #ifdef TARGET_MAC
      sys_nr &= 0xFFFFFF;
    #endif
    arg1 = PIN_GetSyscallArgument(ctxt, std, 1);
    if (sys_nr < MAX_SYSCALL_NUM) {
      fprintf(strace_file, "%u %u %s(", logstate->changelist_number, logstate->this_pid, syscalls[sys_nr].name);
      int first = 1;
      int i;
      for (i=0;i<syscalls[sys_nr].nargs; i++) {
        if (first == 0) {
          fprintf(strace_file, ", ");
        } else {
          first = 0;
        }
        void *arg = (void *)PIN_GetSyscallArgument(ctxt, std, i);
        switch (syscalls[sys_nr].args[i]) {
          case ARG_STR: {
            char buffer[104];
            memcpy(&buffer[100], "...", 4);
            PIN_SafeCopy(buffer, arg, 100);
            fprintf(strace_file, "%p=\"%s\"", arg, (char *)buffer);
            break;
          }
          case ARG_INT:
            fprintf(strace_file, "%lu", (long)arg);
            break;
          case ARG_PTR:
          default:
            fprintf(strace_file, "%p", (void *)arg);
            break;
        }
      }

      fflush(strace_file);
      return;
    } else {
      // Fall thru to no-syscall-knowledge code
    }
  #endif

  fprintf(strace_file, "%u %u %ld(%p, %p, %p, %p, %p, %p",
    logstate->changelist_number, logstate->this_pid,
    (long)PIN_GetSyscallNumber(ctxt, std),
    (void*)PIN_GetSyscallArgument(ctxt, std, 0), (void*)PIN_GetSyscallArgument(ctxt, std, 1), (void*)PIN_GetSyscallArgument(ctxt, std, 2),
    (void*)PIN_GetSyscallArgument(ctxt, std, 3), (void*)PIN_GetSyscallArgument(ctxt, std, 4), (void*)PIN_GetSyscallArgument(ctxt, std, 5)
  );
  fflush(strace_file);
}

VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
	long syscall_return = PIN_GetSyscallReturn(ctxt, std);
	fprintf(strace_file,") = %p\n", (void*)syscall_return);
	fflush(strace_file);
#ifdef TARGET_LINUX
	// geohot doesn't approve of this hack, even though he wrote it
	if (sys_nr == SYS_READ) {
		RecordMemWrite2(arg1, syscall_return);
	}
#endif
}

////////////////////////////////////////////////////////////////
// Other functions
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

VOID ImageLoad(IMG img, VOID *v) {
	static int once = 0;
	if(!once) {
		once = 1;
		std::cerr << "qira: filtering to image " << IMG_Name(img) << std::endl;
		filter_ip_low = IMG_LowAddress(img);
		filter_ip_high = IMG_HighAddress(img)+1;
	}
	
	UINT32 numRegions = IMG_NumRegions(img);
	ADDRINT imglow = IMG_LowAddress(img);
	string imgname = IMG_Name(img);
	
	if(!numRegions) { // TODO: Figure out if this is a windows bug
		fprintf(base_file, "%p-%p %x %s\n", (void*)imglow, (void*)IMG_HighAddress(img), 0, imgname.c_str());
	} else {
		for(UINT32 i = 0; i < numRegions; i++) {
			ADDRINT low = IMG_RegionLowAddress(img, i);
			ADDRINT high = IMG_RegionHighAddress(img, i)+1;
			fprintf(base_file, "%p-%p %zx %s\n", (void*)low, (void*)high, (size_t)(low - imglow), imgname.c_str());
		}
	}
	fflush(base_file);

	if(KnobMakeStandaloneTrace) {
		// Dump image file here.
		FILE *f = fopen((*image_folder+urlencode(imgname)).c_str(), "wb");
		ASSERT(f, "Couldn't open image file destination.");
		fwrite((void*)IMG_StartAddress(img), 1, IMG_SizeMapped(img), f);
		fclose(f);
	}
}

VOID ThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v) {
	static int x = 0;
	ASSERT(x++ == 0, "Beta, please wait to unlock more than one thread.");
	PIN_SetContextReg(ctxt, writeea_scratch_reg, 0);
}

VOID ThreadFini(THREADID tid, const CONTEXT *ctxt, INT32 code, VOID *v) {
	ASSERT(PIN_GetContextReg(ctxt, writeea_scratch_reg) == 0, "o_O");
}

VOID Fini(INT32 code, VOID *v) {
	CLOSE_TRACEFILE(trace_file);
}

VOID ForkChild(THREADID threadid, const CONTEXT *ctx, VOID *v) {
	new_trace_files(true);
	logstate->parent_id = logstate->this_pid;
	logstate->this_pid = file_id;
	logstate->first_changelist_number = logstate->changelist_number;
	logstate->change_count = 1;
}

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

	new_trace_files();
	logstate->change_count = 1;
	logstate->changelist_number = 0;
	logstate->is_filtered = 0;
	logstate->first_changelist_number = 0;
	logstate->parent_id = -1;
	logstate->this_pid = file_id;

	PIN_AddFiniFunction(Fini, 0);

	IMG_AddInstrumentFunction(ImageLoad, 0);

	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	INS_AddInstrumentFunction(Instruction, 0);

	PIN_AddSyscallEntryFunction(SyscallEntry, 0);
	PIN_AddSyscallExitFunction(SyscallExit, 0);

#ifndef TARGET_WINDOWS
	PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, ForkChild, 0);
	// TODO: Look into InstLib follow child for following execves (and windows equiv)
#endif

	PIN_StartProgram();
}

