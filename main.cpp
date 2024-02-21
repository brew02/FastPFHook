#include <Windows.h>
#include <stdio.h>
#include <intrin.h>

#include <Zydis/Zydis.h>

// Add credits to MinHook author and SMAP Btbd

#define PAGE_SIZE 0x1000
#define PAGE_ALIGN(address) (UINT_PTR)(address) & (~0xFFFllu)
#define INITIAL_HOOK_SIZE 2 * PAGE_SIZE
#define JMP_SIZE_32 5
#define JMP_SIZE_ABS 14
#define MANUAL_RET_SIZE 13

#define GP_REGISTER_COUNT (ZYDIS_REGISTER_R15 - ZYDIS_REGISTER_RAX) + 1

#define TRAP_FLAG 0b100000000llu

#define EXCEPTION_INFORMATION_EXECUTION 8

#define RVA(base, address) reinterpret_cast<UINT64>(base) - reinterpret_cast<UINT64>(address)

struct HookData
{
	UINT8* modifiedPagesStart;
	UINT8* modifiedPagesEnd;
	UINT8* hookAddress;
	UINT8* hookPageStart;
	UINT8* hookPageEnd;
	UINT8* originalInstructionStart;
	UINT8* originalInstructionEnd;
	UINT8* relocationCursorStart;
	UINT8* relocationCursor;
	UINT64 mpSize;
	UINT8 topBoundaryInstructionLength;
};

struct Disassembler
{
	ZydisDecoder decoder;
	ZydisDecoderContext context;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	UINT8* address;
};

void* gExceptionHandlerHandle = nullptr;
HookData singleHook;

class PFHook
{
public:
	UINT8* mNewPages;
	UINT8* mOriginalAddress;
	UINT8* mRelocCursor;
	UINT64 mNewPageSize;

	PFHook(void* newPages, void* originalAddress, UINT64 newPageSize)
	{
		mNewPages = reinterpret_cast<UINT8*>(newPages);
		mOriginalAddress = reinterpret_cast<UINT8*>(originalAddress);
		mRelocCursor = mNewPages + PAGE_SIZE + ZYDIS_MAX_INSTRUCTION_LENGTH * 2 + JMP_SIZE_ABS;
		mNewPageSize = newPageSize;
	}

	__forceinline UINT8* NewPagesEnd()
	{
		return mNewPages + mNewPageSize;
	}

	__forceinline UINT8* OriginalPage()
	{
		return reinterpret_cast<UINT8*>(PAGE_ALIGN(mOriginalAddress));
	}

	__forceinline UINT8* OriginalPageEnd()
	{
		return OriginalPage() + PAGE_SIZE;
	}

	__forceinline UINT8* NewPagesInstructions()
	{
		return mNewPages + ZYDIS_MAX_INSTRUCTION_LENGTH;
	}

	__forceinline UINT8* NewPagesInstructionsEnd()
	{
		return NewPagesInstructions() + PAGE_SIZE;
	}

	// Might require further changes or an additional function/parameter
	// for small relative instructions converted to a larger one.
	__forceinline UINT8* OriginalToNew(void* originalAddress)
	{
		return NewPagesInstructions() + (reinterpret_cast<UINT8*>(originalAddress) - OriginalPage());
	}

	bool Relocate(const void* buffer, size_t length)
	{
		if ((mRelocCursor + length) >= NewPagesEnd())
		{
			// extend
			mNewPageSize += PAGE_SIZE;

			UINT8* oldNewPages = mNewPages;

			mNewPages = reinterpret_cast<UINT8*>(VirtualAlloc(nullptr,
				mNewPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));

			if (!mNewPages)
				return false;

			memset(mNewPages, 0xCC, mNewPageSize);
			memcpy(mNewPages, oldNewPages, mNewPageSize - PAGE_SIZE);

			mRelocCursor = mNewPages + (mRelocCursor - oldNewPages);

			VirtualFree(oldNewPages, 0, MEM_RELEASE);
		}

		memcpy(mRelocCursor, buffer, length);
		mRelocCursor += length;

		return true;
	}
};

PFHook* tempPFHook = nullptr;

// More TODOs: Adding multi-threading support (locks), split code into different files, 
// read comment about unconditional branches below (somewhere)
// Use classes for the Disassembler struct and the HookData struct

// Short relative instructions will cause a problem with this current method
// because a direct translation from the original page to the modified page
// will cause the instruction pointer to be in the middle of one of our jumps.
// 
// We should keep a database for translations that fall within these criteria (there are very few)
//

bool ParseAndTranslate(HookData* hookData, UINT8* address, bool parseBranch, bool topInstruction);
bool ParseAndTranslateSingleInstruction(Disassembler* disassembler, HookData* hookData, bool parseBranch, bool topInstruction);

bool SafeRelocate(HookData* hookData, const void* buffer, size_t length)
{
	if ((hookData->relocationCursor + length) >= hookData->modifiedPagesEnd)
	{
		// extend
		hookData->mpSize += PAGE_SIZE;
		UINT8* newMP = reinterpret_cast<UINT8*>(VirtualAlloc(nullptr, 
			hookData->mpSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));

		if (!newMP)
			return false;

		memset(newMP, 0xCC, hookData->mpSize);
		memcpy(newMP, hookData->modifiedPagesStart, hookData->mpSize - PAGE_SIZE);

		UINT8* oldMP = hookData->modifiedPagesStart;

		hookData->relocationCursor = newMP + (hookData->relocationCursor - oldMP);
		hookData->relocationCursorStart = newMP + (hookData->relocationCursorStart - oldMP);
		hookData->originalInstructionStart = newMP + ZYDIS_MAX_INSTRUCTION_LENGTH;
		hookData->originalInstructionEnd = singleHook.relocationCursorStart - (ZYDIS_MAX_INSTRUCTION_LENGTH + JMP_SIZE_ABS);
		hookData->modifiedPagesStart = newMP;
		hookData->modifiedPagesEnd = newMP + hookData->mpSize;

		VirtualFree(oldMP, 0, MEM_RELEASE);
	}

	memcpy(hookData->relocationCursor, buffer, length);
	hookData->relocationCursor += length;

	return true;
}

ZyanStatus InitializeDisassembler(Disassembler* disassembler, ZydisMachineMode machineMode, ZydisStackWidth stackWidth, UINT8* address)
{
	ZeroMemory(disassembler, sizeof(Disassembler));
	disassembler->address = address;
	return ZydisDecoderInit(&disassembler->decoder, machineMode, stackWidth);
}

__forceinline void NextInstruction(Disassembler* disassembler)
{
	disassembler->address += disassembler->instruction.length;
}

ZyanStatus Disassemble(Disassembler* disassembler, UINT_PTR length)
{
	return ZydisDecoderDecodeFull(&disassembler->decoder, disassembler->address,
		length, &disassembler->instruction, disassembler->operands);;
}



// Create separate functions for access violations, breakpoints, and single-steps
long __stdcall ExceptionHandler(EXCEPTION_POINTERS* exceptionInfo)
{
	EXCEPTION_RECORD* exceptionRecord = exceptionInfo->ExceptionRecord;
	CONTEXT* contextRecord = exceptionInfo->ContextRecord;
	UINT8* rip = reinterpret_cast<UINT8*>(contextRecord->Rip);



	if (exceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
		(rip >= (singleHook.hookPageStart - (ZYDIS_MAX_INSTRUCTION_LENGTH - 1)) && // At least 1 byte is on this page (hence the exception)
			rip < singleHook.hookPageEnd))
	{
		if (rip < singleHook.hookPageStart)
		{
			if (exceptionRecord->NumberParameters == 0 || 
				exceptionRecord->ExceptionInformation[0] != EXCEPTION_INFORMATION_EXECUTION)
			{
				return EXCEPTION_CONTINUE_SEARCH;
			}

			if (singleHook.topBoundaryInstructionLength == 0)
			{
				Disassembler disassembler;
				if (ZYAN_FAILED(InitializeDisassembler(&disassembler, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64, rip)))
				{
					return EXCEPTION_CONTINUE_SEARCH;
				}

				if (ZYAN_FAILED(Disassemble(&disassembler, ZYDIS_MAX_INSTRUCTION_LENGTH)))
				{
					return EXCEPTION_CONTINUE_SEARCH;
				}

				UINT8 bytesAbove = static_cast<UINT8>(singleHook.hookPageStart - rip);
				UINT8 length = disassembler.instruction.length;
				
				if ((rip + length) < singleHook.hookPageStart)
				{
					return EXCEPTION_CONTINUE_SEARCH;
				}

				UINT8 bytesBelow = length - bytesAbove;
				singleHook.topBoundaryInstructionLength = length;

				memset(singleHook.modifiedPagesStart, 0x90, ZYDIS_MAX_INSTRUCTION_LENGTH + bytesBelow);
				ParseAndTranslateSingleInstruction(&disassembler, &singleHook, false, true);

				// Add additional code to the breakpoint handler and single step handler to account for this
			}
			else if ((rip + singleHook.topBoundaryInstructionLength) < singleHook.hookPageStart)
			{
				return EXCEPTION_CONTINUE_SEARCH;
			}

			contextRecord->Rip = reinterpret_cast<UINT64>(singleHook.modifiedPagesStart);
		}
		else
		{
			contextRecord->Rip = reinterpret_cast<UINT64>(
				singleHook.originalInstructionStart + (rip - singleHook.hookPageStart));
		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (exceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT &&
		(rip >= singleHook.modifiedPagesStart && rip < singleHook.originalInstructionEnd))
	{
		// Perform additional analysis on rip and the branch to work
		ParseAndTranslate(&singleHook, singleHook.hookPageStart + (rip - singleHook.originalInstructionStart), true, false);
		contextRecord->EFlags |= TRAP_FLAG;
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (exceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP &&
		(rip >= singleHook.modifiedPagesStart && rip < singleHook.originalInstructionEnd))
	{
		ParseAndTranslate(&singleHook, singleHook.hookPageStart + (rip - singleHook.originalInstructionStart), false, false);
		contextRecord->EFlags &= ~(TRAP_FLAG);
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

void PlaceRelativeJump(void* destination, INT32 offset)
{
	// jmp offset
	UINT8 instruction[JMP_SIZE_32] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
	*(INT32*)(&instruction[1]) = offset;

	memcpy(destination, instruction, JMP_SIZE_32);
}

void PlaceAbsoluteJump(void* destination, UINT64 address)
{
	// jmp [rip]
	// rip -> address
	UINT8 instruction[JMP_SIZE_ABS] = 
	{ 
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00 , 0x00, 0x00, 0x00, 0x00 
	};

	*(UINT64*)(&instruction[6]) = address;

	memcpy(destination, instruction, JMP_SIZE_ABS);
}

void PlaceManualReturnAddress(void* destination, UINT64 returnAddress)
{
	// push imm
	// mov dword ptr [rsp, 4], imm
	UINT8 instructions[MANUAL_RET_SIZE] = 
	{ 
		0x68, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x44, 
		0x24, 0x04, 0x00, 0x00, 0x00, 0x00 
	};

	*reinterpret_cast<UINT32*>(&instructions[1]) = static_cast<UINT32>(returnAddress);
	*reinterpret_cast<UINT32*>(&instructions[9]) = static_cast<UINT32>(returnAddress >> 32);

	memcpy(destination, instructions, MANUAL_RET_SIZE);
}

bool PlaceRelativeJump(HookData* hookData, INT32 offset)
{
	// jmp offset
	UINT8 instruction[JMP_SIZE_32] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
	*(INT32*)(&instruction[1]) = offset;

	return SafeRelocate(hookData, instruction, JMP_SIZE_32);
}

bool PlaceAbsoluteJump(HookData* hookData, UINT64 address)
{
	// jmp [rip]
	// rip -> address
	UINT8 instruction[JMP_SIZE_ABS] =
	{
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00 , 0x00, 0x00, 0x00, 0x00
	};

	*(UINT64*)(&instruction[6]) = address;

	return SafeRelocate(hookData, instruction, JMP_SIZE_ABS);
}

bool PlaceAbsoluteJumpAndBreak(HookData* hookData, UINT64 address)
{
	// jmp [rip]
	// rip -> address
	UINT8 instruction[JMP_SIZE_ABS] =
	{
		0xCC, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00 , 0x00, 0x00, 0x00, 0x00
	};

	*(UINT64*)(&instruction[6]) = address;

	return SafeRelocate(hookData, instruction, JMP_SIZE_ABS);
}

bool PlaceManualReturnAddress(HookData* hookData, UINT64 returnAddress)
{
	// push imm
	// mov dword ptr [rsp, 4], imm
	UINT8 instructions[MANUAL_RET_SIZE] =
	{
		0x68, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x44,
		0x24, 0x04, 0x00, 0x00, 0x00, 0x00
	};

	*reinterpret_cast<UINT32*>(&instructions[1]) = static_cast<UINT32>(returnAddress);
	*reinterpret_cast<UINT32*>(&instructions[9]) = static_cast<UINT32>(returnAddress >> 32);

	return SafeRelocate(hookData, instructions, MANUAL_RET_SIZE);
}

// Credits to btbd (SMAP)
// Note: ZYDIS_REGISTER_INVALID is a custom definition
ZydisRegister ConvertGPRegisterToIndex(ZydisRegister reg)
{
	if (reg > ZYDIS_REGISTER_R15 || reg < ZYDIS_REGISTER_AL)
		return ZYDIS_REGISTER_INVALID;

	// Account for the 4 upper registers
	if (reg >= ZYDIS_REGISTER_AH)
		reg = (ZydisRegister)(reg - 4);

	return (ZydisRegister)((reg - ZYDIS_REGISTER_AL) % GP_REGISTER_COUNT);
}

ZydisRegister GetUnusedGPRegister(ZydisDecodedInstruction* instruction, ZydisDecodedOperand* operands)
{
	ZydisRegister AvailableRegisters[GP_REGISTER_COUNT] =
	{
		ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_RBX,
		ZYDIS_REGISTER_INVALID, ZYDIS_REGISTER_RBP, ZYDIS_REGISTER_RSI, ZYDIS_REGISTER_RDI,
		ZYDIS_REGISTER_R8,  ZYDIS_REGISTER_R9, ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R11,
		ZYDIS_REGISTER_R12, ZYDIS_REGISTER_R13, ZYDIS_REGISTER_R14, ZYDIS_REGISTER_R15
	};

	for (UINT8 i = 0; i < instruction->operand_count; i++)
	{
		ZydisDecodedOperand* operand = &operands[i];
		ZydisRegister reg1 = ZYDIS_REGISTER_INVALID;
		ZydisRegister reg2 = ZYDIS_REGISTER_INVALID;

		if (operand->type == ZYDIS_OPERAND_TYPE_REGISTER)
		{
			reg1 = ConvertGPRegisterToIndex(operand->reg.value);
		}
		else if (operand->type == ZYDIS_OPERAND_TYPE_MEMORY)
		{
			reg1 = ConvertGPRegisterToIndex(operand->mem.base);
			reg2 = ConvertGPRegisterToIndex(operand->mem.index);
		}

		if (reg1 != ZYDIS_REGISTER_INVALID)
			AvailableRegisters[reg1] = ZYDIS_REGISTER_INVALID;

		if (reg2 != ZYDIS_REGISTER_INVALID)
			AvailableRegisters[reg2] = ZYDIS_REGISTER_INVALID;
	}

	for (int i = 0; i < GP_REGISTER_COUNT; i++)
		if (AvailableRegisters[i] != ZYDIS_REGISTER_INVALID)
			return AvailableRegisters[i];

	return ZYDIS_REGISTER_INVALID;
}

// We need to deal with double branches
// Ex.
// jcc (2 bytes)
// jmp (x bytes)
//
ZyanStatus PlaceAbsoluteInstruction(PFHook* pfHook, UINT64 rip,
	ZydisDecodedInstruction* instruction, ZydisDecodedOperand* operands)
{
	UINT8 buffer[ZYDIS_MAX_INSTRUCTION_LENGTH];
	ZyanUSize length = sizeof(buffer);
	ZyanStatus status = 0;
	ZydisEncoderRequest request;
	ZeroMemory(&request, sizeof(request));

	ZydisRegister reg = GetUnusedGPRegister(instruction, operands);
	if (reg == ZYDIS_REGISTER_INVALID)
		return ZYAN_STATUS_FAILED;

	if (instruction->meta.branch_type != ZYDIS_BRANCH_TYPE_NONE)
	{
		if (instruction->meta.category == ZYDIS_CATEGORY_CALL)
		{
			if (!PlaceManualReturnAddress(hookData, (UINT64)(*hookData->relocationCursor + MANUAL_RET_SIZE + JMP_SIZE_ABS)))
				return ZYAN_STATUS_FAILED;
		}
		else if (instruction->meta.category == ZYDIS_CATEGORY_COND_BR)
		{
			request.mnemonic = instruction->mnemonic;
			request.machine_mode = instruction->machine_mode;
			request.operand_count = instruction->operand_count_visible;
			request.operands[0].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
			request.operands[0].imm.u = 0x2;
			request.branch_type = ZYDIS_BRANCH_TYPE_NONE;
			request.branch_width = ZYDIS_BRANCH_WIDTH_NONE;
			status = ZydisEncoderEncodeInstruction(&request, buffer, &length);
			if (ZYAN_FAILED(status))
				return status;

			// jcc rip+0x2
			if (!SafeRelocate(hookData, buffer, length))
				return ZYAN_STATUS_FAILED;

			// jmp rip+0xE
			if (!SafeRelocate(hookData, "\xEB\x0E", 2))
				return ZYAN_STATUS_FAILED;
		}

		UINT8* branchDestination = reinterpret_cast<UINT8*>(rip + operands[0].imm.value.s);
		if (branchDestination < hookData->hookPageStart || branchDestination >= hookData->hookPageEnd)
		{
			if (!PlaceAbsoluteJump(hookData, reinterpret_cast<UINT64>(branchDestination)))
				return ZYAN_STATUS_FAILED;
		}
		else
		{
			/* We still need more checks to make sure that the top instruction
			is considered (probably some changes need to be made below as well) 
			*/

			//PlaceRelativeJump(hookData, )
			if (!PlaceAbsoluteJump(hookData, reinterpret_cast<UINT64>(hookData->originalInstructionStart + (branchDestination - hookData->hookPageStart))))
				return ZYAN_STATUS_FAILED;
		}

		return ZYAN_STATUS_SUCCESS;
	}

	request.mnemonic = ZYDIS_MNEMONIC_PUSH;
	request.machine_mode = instruction->machine_mode;
	request.operand_count = 1;
	request.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
	request.operands[0].reg.value = reg;

	status = ZydisEncoderEncodeInstruction(&request, buffer, &length);
	if (ZYAN_FAILED(status))
		return status;

	if (!SafeRelocate(hookData, buffer, length))
		return ZYAN_STATUS_FAILED;

	length = sizeof(buffer);
	ZeroMemory(&request, sizeof(request));
	request.mnemonic = ZYDIS_MNEMONIC_MOV;
	request.machine_mode = instruction->machine_mode;
	request.operand_count = 2;
	request.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
	request.operands[0].reg.value = reg;
	request.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
	request.operands[1].imm.u = rip;

	status = ZydisEncoderEncodeInstruction(&request, buffer, &length);
	if (ZYAN_FAILED(status))
		return status;

	if (!SafeRelocate(hookData, buffer, length))
		return ZYAN_STATUS_FAILED;

	length = sizeof(buffer);
	ZeroMemory(&request, sizeof(request));
	if (ZYAN_FAILED(ZydisEncoderDecodedInstructionToEncoderRequest(instruction, operands, instruction->operand_count_visible, &request)))
		return false;

	for (int i = 0; i < request.operand_count; i++)
	{
		ZydisEncoderOperand* operand = &request.operands[i];
		if (operand->type == ZYDIS_OPERAND_TYPE_MEMORY &&
			operand->mem.base == ZYDIS_REGISTER_RIP)
		{
			operand->mem.base = reg;
			break;
		}
	}

	status = ZydisEncoderEncodeInstruction(&request, buffer, &length);
	if (ZYAN_FAILED(status))
		return status;

	if (!SafeRelocate(hookData, buffer, length))
		return ZYAN_STATUS_FAILED;

	length = sizeof(buffer);
	ZeroMemory(&request, sizeof(request));

	request.mnemonic = ZYDIS_MNEMONIC_POP;
	request.machine_mode = instruction->machine_mode;
	request.operand_count = 1;
	request.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
	request.operands[0].reg.value = reg;

	status = ZydisEncoderEncodeInstruction(&request, buffer, &length);
	if (ZYAN_FAILED(status))
		return status;

	if (!SafeRelocate(hookData, buffer, length))
		return ZYAN_STATUS_FAILED;

	return true;
}

// Messy but working (change the hookData->originalInstructionStart +... stuff)
bool TranslateRelativeInstruction(PFHook* pfHook, Disassembler* disassembler, bool topInstruction)
{
	ZydisDecodedInstruction* instruction = &disassembler->instruction;
	ZydisDecodedOperand* operands = disassembler->operands;

	INT32 relocationRVA = static_cast<INT32>(pfHook->mRelocCursor - (topInstruction ? 
		pfHook->mNewPages : pfHook->OriginalToNew(disassembler->address) + JMP_SIZE_32));

	UINT32 offset = static_cast<UINT32>(disassembler->address - pfHook->OriginalPage());

	UINT8 totalLength = 0;

	while (true)
	{
		if (instruction->attributes & ZYDIS_ATTRIB_IS_RELATIVE)
		{
			if (ZYAN_FAILED(PlaceAbsoluteInstruction(pfHook,
				reinterpret_cast<UINT64>(disassembler->address) + instruction->length,
				instruction, operands)))
			{
				return false;
			}
		}
		else
		{
			if (!pfHook->Relocate(disassembler->address, instruction->length))
				return false;
		}

		totalLength += instruction->length;

		if ((disassembler->address + instruction->length) >= pfHook->OriginalPageEnd() ||
			totalLength >= JMP_SIZE_32)
		{
			break;
		}
		else
		{
			if (topInstruction)
				break;

			NextInstruction(disassembler);
			if (ZYAN_FAILED(Disassemble(disassembler, ZYDIS_MAX_INSTRUCTION_LENGTH)))
				return false;
		}
	}

	// Jump to the relocation page from the new page
	PlaceRelativeJump((topInstruction ? pfHook->mNewPages : 
		pfHook->NewPagesInstructions() + offset), relocationRVA);

	// All needs fixing!
	if (!topInstruction)
	{
		ZydisEncoderNopFill(pfHook->NewPagesInstructions() + offset + JMP_SIZE_32, totalLength - JMP_SIZE_32);
	}

	// Jump back to the new page from the relocation page
	if (!PlaceRelativeJump(pfHook, static_cast<INT32>((topInstruction ? (pfHook->mNewPages + JMP_SIZE_32) : 
		pfHook->OriginalToNew(disassembler->address) + instruction->length) - (pfHook->mRelocCursor + JMP_SIZE_32))))
	{
		return false;
	}

	return true;
}

bool VerifyInstruction(UINT8* address, UINT8 length)
{
	for (UINT8 i = 0; i < length; i++)
		if (*(address + i) != 0xCC)
			return false;

	return true;
}

bool ParseAndTranslateSingleInstruction(Disassembler* disassembler, PFHook* pfHook, bool parseBranch, bool topInstruction)
{
	ZydisDecodedInstruction* instruction = &disassembler->instruction;

	// This may need to be changed
	UINT8* mpAddress = topInstruction ? pfHook->mNewPages : pfHook->OriginalToNew(disassembler->address);

	if (instruction->attributes & ZYDIS_ATTRIB_IS_RELATIVE)
	{
		//if (instruction->meta.branch_type != ZYDIS_BRANCH_TYPE_NONE)
		//{
		//	UINT8* mpBranchAddress = mpAddress + 
		//		instruction->length + disassembler->operands[0].imm.value.s;

		//	if ((mpBranchAddress >= hookData->originalInstructionStart &&
		//		mpBranchAddress < hookData->originalInstructionEnd))
		//	{
		//		if (!parseBranch)
		//			return true;
		//		// Relative CONDITIONAL branches should be taken care of, at least
		//		// for opaque predicates, but a better approach that would allow for
		//		// better analysis would be to leave the breakpoints on the branching
		//		// instructions themselves, and then single-step to the next instruction,
		//		// thus letting the hardware do the heavy lifting.
		//		// There are still extreme circumstances where unconditional branches
		//		// using other registers as displacement could cause issues (think about it).

		//		// Potential fix, check for specific circumstances:
		//		// lea reg1, [rip]
		//		// add reg1, reg2 
		//		// unconditional branch [reg1]
		//		// Translate such a branch so that an absolute address jumping
		//		// to the original page is calculated. Handle bad branches in the
		//		// page fault handler.

		//		memcpy(mpAddress, disassembler->address, instruction->length);
		//		return true;
		//	}
		//}

		if (!TranslateRelativeInstruction(pfHook, disassembler, topInstruction))
			return false;
	}
	else
	{
		memcpy(mpAddress, disassembler->address, instruction->length);
	}

	return true;
}

bool ParseAndTranslate(PFHook* pfHook, UINT8* address, bool parseBranch, bool topInstruction)
{
	Disassembler disassembler;
	if (ZYAN_FAILED(InitializeDisassembler(&disassembler,
		ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64, address)))
	{
		return false;
	}

	for (; (disassembler.address >= pfHook->OriginalPage()) && 
		(disassembler.address < pfHook->OriginalPageEnd());
		NextInstruction(&disassembler))
	{
		if (ZYAN_FAILED(Disassemble(&disassembler, 
			ZYDIS_MAX_INSTRUCTION_LENGTH)))
		{
			return false;
		}

		ZydisDecodedInstruction* instruction = &disassembler.instruction;

		// Don't make passes over analyzed instructions
		if (!VerifyInstruction(pfHook->OriginalToNew(
			disassembler.address), instruction->length))
		{
			break;
		}

		if (!ParseAndTranslateSingleInstruction(&disassembler, pfHook, parseBranch, topInstruction))
			return false;

		// Maybe move this above the ParseAndTranslateSingleInstruction for accurate branch parsing
		// I think that this will require single-step exceptions
		if (instruction->mnemonic == ZYDIS_MNEMONIC_INT3)
		{
			break;
		}
	}

	if (disassembler.address >= pfHook->OriginalPageEnd())
	{
		PlaceAbsoluteJump(pfHook->OriginalToNew(disassembler.address), 
			reinterpret_cast<UINT64>(disassembler.address));
	}

	return true;
}

bool InstallHook(void* address)
{
	void* newPage = VirtualAlloc(nullptr, INITIAL_HOOK_SIZE,
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!newPage)
		return false;

	memset(newPage, 0xCC, INITIAL_HOOK_SIZE);

	tempPFHook = new PFHook(newPage, address, INITIAL_HOOK_SIZE);

	return ParseAndTranslate(tempPFHook, tempPFHook->mOriginalAddress, false, false);
}

void RemoveHook(void* address)
{
	// Finish this later
}

bool InitializePFH()
{
	gExceptionHandlerHandle = AddVectoredExceptionHandler(true, ExceptionHandler);
	if (!gExceptionHandlerHandle)
		return false;

	return true;
}

void UninitializePFH()
{
	RemoveVectoredExceptionHandler(gExceptionHandlerHandle);
}

int main()
{
	if (!InitializePFH())
		return -1;

	InstallHook(&MessageBoxA);

	UINT8* messageBoxA = singleHook.originalInstructionStart + (singleHook.hookAddress - singleHook.hookPageStart);
	((decltype(MessageBoxA)*)(messageBoxA))(nullptr, "Test", nullptr, MB_ICONWARNING);

	UninitializePFH();

	return 0;
}