#include <stdio.h>
#include <time.h>
#include "pin.H"

#ifdef TARGET_MAC
#define NOADDSYSCALLFUNC 1 // PIN_AddSyscallEntryFunction and PIN_AddSyscallExitFunction are unsupported
#endif

#ifndef TARGET_WINDOWS
#define InterlockedIncrement(x) __sync_add_and_fetch((x), 1)
#endif

#define IS_VALID    0x80000000
#define IS_WRITE    0x40000000
#define IS_MEM      0x20000000
#define IS_START    0x10000000
#define IS_SYSCALL  0x08000000
#define SIZE_MASK   0xFF

struct {
	uint32_t change_count;
	uint32_t changelist_number;
	uint32_t is_filtered;
	uint32_t first_changelist_number;
	uint32_t parent_id;
	uint32_t this_pid;
} logstate;

FILE *trace_file = NULL;
FILE *strace_file = NULL;
FILE *base_file = NULL;
unsigned char trace_file_buffer[16<<10];
void new_trace_files() {
	char pathbase[1024];
	char path[1024];
	sprintf(pathbase, "/tmp/qira_logs/%ld%d", time(NULL), PIN_GetPid());
	
	if(trace_file) fpurge(trace_file), fclose(trace_file);
	trace_file = fopen(pathbase, "w");
	
	if(strace_file) fpurge(strace_file), fclose(strace_file);
	sprintf(path, "%s_strace", pathbase);
	strace_file = fopen(path, "w");
	
	if(base_file) fpurge(base_file), fclose(base_file);
	sprintf(path, "%s_base", pathbase);
	base_file = fopen(path, "w");
}

static inline void add_change(uint64_t addr, uint64_t data, uint32_t flags) {
	struct {
		uint64_t address;
		uint64_t data;
		uint32_t changelist_number;
		uint32_t flags;
	} change = {
		.address = addr,
		.data = data,
		.changelist_number = logstate.changelist_number,
		.flags = flags|IS_VALID,
	};
	fwrite(&change, sizeof(change), 1, trace_file);
	logstate.change_count++;
}

REG writeea_scratch_reg;

////////////////////////////////////////////////////////////////
// Memory & register instrumentation functions
////////////////////////////////////////////////////////////////

// TODO: See if merging analysis routines improves perf.

VOID RecordStart(ADDRINT ip, UINT32 size) {
	logstate.changelist_number++;
	add_change(ip, size, IS_START);
}

VOID RecordRegRead(PIN_REGISTER *value, UINT32 size, UINT32 reg) {
	for(UINT32 i = 0; i*8 < size; i++) {
		add_change(reg+i, value->qword[i], 8);
	}
}

VOID RecordRegWrite(PIN_REGISTER *value, UINT32 size, UINT32 reg) {
	for(UINT32 i = 0; i*8 < size; i++) {
		add_change(reg+i, value->qword[i], IS_WRITE|8);
	}
}

VOID RecordMemRead(ADDRINT addr, UINT32 size) {
	UINT64 value;
	PIN_SafeCopy(&value, (const VOID *)addr, size); // Can assume it worked.
	add_change(addr, value, IS_MEM);
}

ADDRINT RecordMemWrite1(ADDRINT addr, ADDRINT oldval) {
	ASSERT(oldval == 0, "This is why you can't have nice things.");
	return addr;
}
ADDRINT RecordMemWrite2(ADDRINT addr, UINT32 size) {
	UINT64 value;
	PIN_SafeCopy(&value, (const VOID *)addr, size); // Can assume it worked.
	add_change(addr, value, IS_MEM|IS_WRITE);
	return 0;
}

VOID RecordSyscall(ADDRINT num) {
	add_change(num, 0, IS_SYSCALL);
}

UINT32 RegToQiraNo(REG r) {
	return r; // TODO: FIXME
}

VOID Instruction(INS ins, VOID *v) {
	// TODO: Do Trace/BBL as per MemTrace example, and lock per BB to support threads.

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
		if(REG_is_flags(r)) continue; //bleh
		if(REG_is_fr(r)) continue; //bleh
		INS_InsertPredicatedCall(
			ins, IPOINT_BEFORE, (AFUNPTR)RecordRegRead,
			IARG_REG_CONST_REFERENCE, r,
			IARG_UINT32, REG_Size(r),
			IARG_UINT32, RegToQiraNo(r),
			IARG_END
		);
	}

	for(UINT32 i = 0; i < wRegs; i++) {
		REG r = INS_RegW(ins, i);
		if(REG_is_flags(r)) continue; //bleh
		if(REG_is_fr(r)) continue; //bleh
		if(INS_HasFallThrough(ins)) {
			INS_InsertPredicatedCall(
				ins, IPOINT_AFTER, (AFUNPTR)RecordRegWrite,
				IARG_REG_CONST_REFERENCE, r,
				IARG_UINT32, REG_Size(r),
				IARG_UINT32, RegToQiraNo(r),
				IARG_END
			);
		}
		if(INS_IsBranchOrCall(ins)) {
			INS_InsertPredicatedCall(
				ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)RecordRegWrite,
				IARG_REG_CONST_REFERENCE, r,
				IARG_UINT32, REG_Size(r),
				IARG_UINT32, RegToQiraNo(r),
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
	fprintf(strace_file, "%p: %ld(%p, %p, %p, %p, %p, %p)",
		(void*)ip, (long)num,
		(void*)arg0, (void*)arg1, (void*)arg2,
		(void*)arg3, (void*)arg4, (void*)arg5
	);
	fflush(strace_file);
}

inline VOID SysAfter(ADDRINT ret) {
	fprintf(strace_file," = %p\n", (void*)ret);
	fflush(strace_file);
}

inline VOID SysNoAfter() {
	fprintf(strace_file," = -\n");
	fflush(strace_file);
}


#ifdef NOADDSYSCALLFUNC

VOID SyscallInstruction(INS ins, VOID *v) {
	if(INS_IsSyscall(ins)) {
		INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SysBefore),
			IARG_INST_PTR, IARG_SYSCALL_NUMBER,
			IARG_SYSARG_VALUE, 0, IARG_SYSARG_VALUE, 1, IARG_SYSARG_VALUE, 2,
			IARG_SYSARG_VALUE, 3, IARG_SYSARG_VALUE, 4, IARG_SYSARG_VALUE, 5,
			IARG_END
		);
		
		if(INS_HasFallThrough(ins)) {
			INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(SysAfter), IARG_SYSRET_VALUE, IARG_END);
		} else {
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SysNoAfter), IARG_CALL_ORDER, CALL_ORDER_LAST, IARG_END);
		}
	}
}

#else

VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
	SysBefore(PIN_GetContextReg(ctxt, REG_INST_PTR),
		PIN_GetSyscallNumber(ctxt, std),
		PIN_GetSyscallArgument(ctxt, std, 0), PIN_GetSyscallArgument(ctxt, std, 1), PIN_GetSyscallArgument(ctxt, std, 2),
		PIN_GetSyscallArgument(ctxt, std, 3), PIN_GetSyscallArgument(ctxt, std, 4), PIN_GetSyscallArgument(ctxt, std, 5)
	);
}

VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
	SysAfter(PIN_GetSyscallReturn(ctxt, std));
}

#endif

////////////////////////////////////////////////////////////////
// Other functions
////////////////////////////////////////////////////////////////

VOID ImageLoad(IMG img, VOID *v) {
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
	if(PIN_Init(argc, argv)) {
		fprintf(stderr, "Error parsing command line.\n");
		return -1;
	}
	PIN_InitSymbols();

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

	PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, ForkChild, 0);
	PIN_AddFiniFunction(Fini, 0);

	IMG_AddInstrumentFunction(ImageLoad, 0);

	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	// TODO: Look into InstLib follow child for following execves (or do it custom)

	INS_AddInstrumentFunction(Instruction, 0);

#ifdef NOADDSYSCALLFUNC
	INS_AddInstrumentFunction(SyscallInstruction, 0);
#else
	PIN_AddSyscallEntryFunction(SyscallEntry, 0);
	PIN_AddSyscallExitFunction(SyscallExit, 0);
#endif

	PIN_StartProgram();
}
