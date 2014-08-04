#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <iostream>

#include "pin.H"

#ifndef TARGET_WINDOWS
#define InterlockedIncrement(x) __sync_add_and_fetch((x), 1)
#endif

#ifdef TARGET_LINUX
#include <stdio_ext.h>
#define fpurge __fpurge
#endif
#ifdef TARGET_WINDOWS
#define fpurge(x) ((void)(x)) // Windows doesn't fork.
#endif

#define IS_VALID    0x80000000
#define IS_WRITE    0x40000000
#define IS_MEM      0x20000000
#define IS_START    0x10000000
#define IS_SYSCALL  0x08000000
#define SIZE_MASK   0xFF

static struct _logstate {
	uint32_t change_count;
	uint32_t changelist_number;
	uint32_t is_filtered;
	uint32_t first_changelist_number;
	uint32_t parent_id;
	uint32_t this_pid;
} logstate;

#ifdef TARGET_WINDOWS
#define TRACE_FILE_BASE "."
#else
#define TRACE_FILE_BASE "/tmp/qira_logs" // This should exist
#endif

FILE *trace_file = NULL;
FILE *strace_file = NULL;
FILE *base_file = NULL;
char trace_file_buffer[16<<10];
void new_trace_files() {
	char pathbase[1024];
	char path[1024];
	sprintf(pathbase, TRACE_FILE_BASE "/%ld%d", time(NULL), PIN_GetPid());
	
	if(trace_file) fpurge(trace_file), fclose(trace_file);
	trace_file = fopen(pathbase, "wb");
	ASSERT(trace_file, "Failed to open trace output.");
	setvbuf(trace_file, trace_file_buffer, _IOFBF, sizeof(trace_file_buffer));
	
	if(strace_file) fpurge(strace_file), fclose(strace_file);
	sprintf(path, "%s_strace", pathbase);
	strace_file = fopen(path, "wb");
	ASSERT(strace_file, "Failed to open trace output.");
	
	if(base_file) fpurge(base_file), fclose(base_file);
	sprintf(path, "%s_base", pathbase);
	base_file = fopen(path, "wb");
	ASSERT(base_file, "Failed to open trace output.");
}

static void add_change(uint64_t addr, uint64_t data, uint32_t flags) {
	struct {
		uint64_t address;
		uint64_t data;
		uint32_t changelist_number;
		uint32_t flags;
	} change;
	change.address = addr;
	change.data = data;
	change.changelist_number = logstate.changelist_number;
	change.flags = flags|IS_VALID;
	fwrite(&change, sizeof(change), 1, trace_file);
	logstate.change_count++;
}

static void add_big_change(uint64_t addr, const void *data, uint32_t flags, size_t size) {
	const UINT64 *v = (const UINT64 *)data;
	while(size >= 8) {
		add_change(addr, *v, flags|8);
		addr += 8; size -= 8; v++;
	}
	if(size) {
		UINT64 x = *v & ~(~(UINT64)0 << size*8);
		add_change(addr, x, flags|size);
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
	logstate.changelist_number++;
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
	ASSERT(size <= sizeof(value), "wow");
	PIN_SafeCopy(value, (const VOID *)addr, size); // Can assume it worked.
	add_big_change(addr, value, IS_MEM|IS_WRITE, size);
	return 0;
}

VOID RecordSyscall(ADDRINT num) {
	add_change(num, 0, IS_SYSCALL);
}

UINT32 RegToQiraRegAddr(REG r) {
	if(sizeof(ADDRINT) == 4) {
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
	} else {
		switch(REG_FullRegName(r)) {
			case REG_GAX: return 0;
			case REG_GCX: return 8;
			case REG_GDX: return 16;
			case REG_GBX: return 24;
			case REG_STACK_PTR: return 32;
			case REG_GBP: return 40;
			case REG_GSI: return 48;
			case REG_GDI: return 56;
			case REG_INST_PTR: return 64;
			default: return 1024;
		}
	}
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
inline VOID SysBefore(ADDRINT ip, ADDRINT num,
	ADDRINT arg0, ADDRINT arg1, ADDRINT arg2,
	ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
}

VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
	fprintf(strace_file, "%p: %ld(%p, %p, %p, %p, %p, %p)",
		(void*)PIN_GetContextReg(ctxt, REG_INST_PTR), (long)PIN_GetSyscallNumber(ctxt, std),
		(void*)PIN_GetSyscallArgument(ctxt, std, 0), (void*)PIN_GetSyscallArgument(ctxt, std, 1), (void*)PIN_GetSyscallArgument(ctxt, std, 2),
		(void*)PIN_GetSyscallArgument(ctxt, std, 3), (void*)PIN_GetSyscallArgument(ctxt, std, 4), (void*)PIN_GetSyscallArgument(ctxt, std, 5)
	);
	fflush(strace_file);
}

VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
	fprintf(strace_file," = %p\n", (void*)PIN_GetSyscallReturn(ctxt, std));
	fflush(strace_file);
}

////////////////////////////////////////////////////////////////
// Other functions
////////////////////////////////////////////////////////////////

VOID ImageLoad(IMG img, VOID *v) {
	static int once = 0;
	if(!once) {
		once = 1;
		std::cerr << "qiraing " << IMG_Name(img) << std::endl;
		filter_ip_low = IMG_LowAddress(img);
		filter_ip_high = IMG_HighAddress(img)+1;
	}
	
	// TODO: Might not be quite right; might neet to step through sections?
	fprintf(base_file, "%p-%p 0 %s\n", (void*)IMG_LowAddress(img), (void*)(IMG_HighAddress(img)+1), IMG_Name(img).c_str());
	fflush(base_file);
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
	fflush(trace_file);
	fseek(trace_file, 0L, SEEK_SET);
	fwrite(&logstate, sizeof(logstate), 1, trace_file);
	fclose(trace_file);
}

VOID ForkChild(THREADID threadid, const CONTEXT *ctx, VOID *v) {
	new_trace_files();
	logstate.parent_id = logstate.this_pid;
	logstate.this_pid = PIN_GetPid();
	logstate.first_changelist_number = logstate.change_count;
	logstate.change_count = 0;
	fwrite(&logstate, sizeof(logstate), 1, trace_file);
}

int main(int argc, char *argv[]) {
	PIN_InitSymbols();
	if(PIN_Init(argc, argv)) {
		fprintf(stderr, "Error parsing command line.\n");
		return -1;
	}

	writeea_scratch_reg = PIN_ClaimToolRegister();
	if(!REG_valid(writeea_scratch_reg)) {
		fprintf(stderr, "Failed to claim a scratch register.\n");
		return 1;
	}

	new_trace_files();
	logstate.change_count = 0;
	logstate.changelist_number = 0;
	logstate.is_filtered = 0;
	logstate.first_changelist_number = 0;
	logstate.parent_id = -1;
	logstate.this_pid = PIN_GetPid();
	fwrite(&logstate, sizeof(logstate), 1, trace_file);

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
