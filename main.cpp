#include <Windows.h>
#include <stdio.h>
#include <intrin.h>

#include <Zydis/Zydis.h>

#include "Internal/hook.h"
// Add credits to MinHook author and SMAP Btbd

struct Disassembler
{
	ZydisDecoder decoder;
	ZydisDecoderContext context;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	UINT8* address;
};

void* gExceptionHandlerHandle = nullptr;

PFHook* tempPFHook = nullptr;

// More TODOs: Adding multi-threading support (locks), split code into different files, 
// read comment about unconditional branches below (somewhere)
// Use classes for the Disassembler struct and the HookData struct

// We may need to make some changes to the conditions that we check for the top and bottom
// instruction on the new page.

bool ParseAndTranslate(PFHook* hook, UINT8* address, bool parseBranch);
bool ParseAndTranslateSingleInstruction(Disassembler* disassembler, PFHook* hook, bool parseBranch);

ZyanStatus InitializeDisassembler(Disassembler* disassembler, ZydisMachineMode machineMode, ZydisStackWidth stackWidth, void* address)
{
	ZeroMemory(disassembler, sizeof(Disassembler));
	disassembler->address = reinterpret_cast<UINT8*>(address);
	return ZydisDecoderInit(&disassembler->decoder, machineMode, stackWidth);
}

__forceinline void NextInstruction(Disassembler* disassembler)
{
	disassembler->address += disassembler->instruction.length;
}

ZyanStatus Disassemble(Disassembler* disassembler, UINT_PTR length)
{
	return ZydisDecoderDecodeFull(&disassembler->decoder, disassembler->address,
		length, &disassembler->instruction, disassembler->operands);
}



// Create separate functions for access violations, breakpoints, and single-steps
long __stdcall ExceptionHandler(EXCEPTION_POINTERS* exceptionInfo)
{
	EXCEPTION_RECORD* exceptionRecord = exceptionInfo->ExceptionRecord;
	CONTEXT* contextRecord = exceptionInfo->ContextRecord;
	UINT8* rip = reinterpret_cast<UINT8*>(contextRecord->Rip);

	if (exceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
		(rip >= tempPFHook->OriginalPageInstructions() && rip < tempPFHook->OriginalPageEnd()))
	{
		if (exceptionRecord->NumberParameters == 0 || 
			exceptionRecord->ExceptionInformation[0] != EXCEPTION_INFORMATION_EXECUTION)
		{
			return EXCEPTION_CONTINUE_SEARCH;
		}

		contextRecord->Rip = reinterpret_cast<UINT64>(tempPFHook->OriginalToNew(rip, true));

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	// There are some bugs here or with the branch handling that
	// deviat from intended behavior, but the program still works.
	// If we translate a relative instruction to an absolute one, we don't need to 
	// single step it or use breakpoints
	else if (exceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT &&
		(rip >= tempPFHook->mNewPages && rip < tempPFHook->NewPagesInstructionsEnd()))
	{
		// Perform additional analysis on rip and the branch to work
		ParseAndTranslate(tempPFHook, tempPFHook->NewToOriginal(rip), true);
		contextRecord->EFlags |= TRAP_FLAG;

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (exceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) 
	{
		if (rip >= tempPFHook->mNewPages && rip < tempPFHook->NewPagesInstructionsEnd())
		{
			ParseAndTranslate(tempPFHook, tempPFHook->NewToOriginal(rip), false);
		}
		
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

// Credits to btbd (SMAP)
// Note: ZYDIS_REGISTER_INVALID is a custom definition added to the enum
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

	for (UINT8 i = 0; i < instruction->operand_count_visible; i++)
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

// Change this so that we don't supply our own RIP (just use the originalRIP)
// We need to handle the two other cases properly as well
UINT8* GetBranchAddress(Disassembler* disassembler, UINT8* newRIP, ZydisOperandType* type)
{
	UINT8* originalRIP = disassembler->address + disassembler->instruction.length;

	for (int i = 0; i < disassembler->instruction.operand_count_visible; i++)
	{
		ZydisDecodedOperand* operand = &disassembler->operands[i];
		if (operand->type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
			operand->imm.is_relative)
		{
			*type = operand->type;
			return newRIP + operand->imm.value.s;
		}
		else if (operand->type == ZYDIS_OPERAND_TYPE_MEMORY &&
			operand->mem.disp.has_displacement)
		{
			*type = operand->type;
			return *reinterpret_cast<UINT8**>(originalRIP + operand->mem.disp.value);
		}
	}

	return nullptr;
}

// We need to deal with double branches (place breakpoints on them properly)
// Ex.
// jcc (2 bytes)
// jmp (x bytes)
//
ZyanStatus PlaceAbsoluteInstruction(PFHook* hook, UINT64 rip,
	Disassembler* disassembler)
{
	ZydisDecodedInstruction* instruction = &disassembler->instruction;
	ZydisDecodedOperand* operands = disassembler->operands;

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
		// We should improve call instructions by making the return
		// address the next instruction on the new page instead
		// of using a jmp
		if (instruction->meta.category == ZYDIS_CATEGORY_CALL)
		{
			if (!hook->PlaceManualReturnAddress(reinterpret_cast<UINT64>(
				hook->mRelocCursor + MANUAL_RET_SIZE + JMP_SIZE_ABS)))
			{
				return ZYAN_STATUS_FAILED;
			}
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
			if (!hook->Relocate(buffer, length))
				return ZYAN_STATUS_FAILED;

			// jmp rip+0xE
			if (!hook->Relocate("\xEB\x0E", 2))
				return ZYAN_STATUS_FAILED;
		}

		// This needs to be cleaned up
		ZydisOperandType type = ZYDIS_OPERAND_TYPE_UNUSED;
		UINT8* branchAddress = GetBranchAddress(disassembler, hook->OriginalToNew(reinterpret_cast<void*>(rip)), &type);
		// Same drill as below (see later function)
		if (!branchAddress)
			return ZYAN_STATUS_FAILED;

		if (branchAddress < hook->mNewPages || branchAddress >= hook->NewPagesInstructionsEnd())
		{
			// Deal with the other two branch types properly
			if (type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
			{
				if (!hook->PlaceAbsoluteJump(reinterpret_cast<UINT64>(hook->NewToOriginal(branchAddress))))
					return ZYAN_STATUS_FAILED;
			}
			else 
			{
				if (!hook->PlaceAbsoluteJump(reinterpret_cast<UINT64>(branchAddress)))
					return ZYAN_STATUS_FAILED;
			}
		}
		else
		{
			// Make this a relative jmp
			if (!hook->PlaceAbsoluteJump(reinterpret_cast<UINT64>(branchAddress)))
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

	if (!hook->Relocate(buffer, length))
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

	if (!hook->Relocate(buffer, length))
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

	if (!hook->Relocate(buffer, length))
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

	if (!hook->Relocate(buffer, length))
		return ZYAN_STATUS_FAILED;

	return true;
}

// Messy but working (change the hookData->originalInstructionStart +... stuff)
bool TranslateRelativeInstruction(PFHook* hook, Disassembler* disassembler)
{
	ZydisDecodedInstruction* instruction = &disassembler->instruction;

	INT32 relocationRVA = static_cast<INT32>(hook->mRelocCursor - 
		(hook->OriginalToNew(disassembler->address) + JMP_SIZE_32));

	UINT32 offset = static_cast<UINT32>(disassembler->address - hook->OriginalPageInstructions());

	UINT8 totalLength = 0;

	while (true)
	{
		if (instruction->attributes & ZYDIS_ATTRIB_IS_RELATIVE)
		{
			if (ZYAN_FAILED(PlaceAbsoluteInstruction(hook,
				reinterpret_cast<UINT64>(disassembler->address) + instruction->length,
				disassembler)))
			{
				return false;
			}
		}
		else
		{
			if (!hook->Relocate(disassembler->address, instruction->length))
				return false;
		}

		totalLength += instruction->length;

		if ((disassembler->address + instruction->length) >= hook->OriginalPageEnd() ||
			totalLength >= JMP_SIZE_32)
		{
			break;
		}
		else
		{
			NextInstruction(disassembler);
			if (ZYAN_FAILED(Disassemble(disassembler, ZYDIS_MAX_INSTRUCTION_LENGTH)))
				return false;

			hook->NewTranslation(disassembler->address, offset);
		}
	}

	// Jump to the relocation page from the new page
	PlaceRelativeJump(hook->mNewPages + offset, relocationRVA);

	ZydisEncoderNopFill(hook->mNewPages + offset + JMP_SIZE_32, static_cast<ZyanUSize>(totalLength) - JMP_SIZE_32);

	// Jump back to the new page from the relocation page
	if (!hook->PlaceRelativeJump(static_cast<INT32>(hook->OriginalToNew(
		disassembler->address) + instruction->length - (hook->mRelocCursor + JMP_SIZE_32))))
	{
		return false;
	}

	return true;
}

UINT8 GetInstructionLengthAtAddress(void* address)
{
	Disassembler disassembler;
	if (ZYAN_FAILED(InitializeDisassembler(
		&disassembler, ZYDIS_MACHINE_MODE_LONG_64, 
		ZYDIS_STACK_WIDTH_64, address)))
	{
		return 0;
	}

	if (ZYAN_FAILED(ZydisDecoderDecodeInstruction(&disassembler.decoder, nullptr,
		address, ZYDIS_MAX_INSTRUCTION_LENGTH, &disassembler.instruction)))
	{
		return 0;
	}
	
	return disassembler.instruction.length;
}

bool VerifyInstruction(UINT8* address, UINT8 length)
{
	for (UINT8 i = 0; i < length; i++)
		if (*(address + i) != 0xCC)
			return false;

	return true;
}

bool ParseAndTranslateSingleInstruction(Disassembler* disassembler, PFHook* hook, bool parseBranch)
{
	ZydisDecodedInstruction* instruction = &disassembler->instruction;
	UINT8* mpAddress = hook->OriginalToNew(disassembler->address);

	if (instruction->attributes & ZYDIS_ATTRIB_IS_RELATIVE)
	{
		if (instruction->meta.branch_type != ZYDIS_BRANCH_TYPE_NONE)
		{
			ZydisOperandType type = ZYDIS_OPERAND_TYPE_UNUSED;
			UINT8* branchAddress = GetBranchAddress(disassembler, mpAddress + instruction->length, &type);
			if (!branchAddress)
				return false;

			if ((branchAddress >= hook->mNewPages &&
				branchAddress < hook->NewPagesInstructionsEnd()))
			{
				if (!parseBranch)
					return false;
				// Relative CONDITIONAL branches should be taken care of, at least
				// for opaque predicates, but a better approach that would allow for
				// better analysis would be to leave the breakpoints on the branching
				// instructions themselves, and then single-step to the next instruction,
				// thus letting the hardware do the heavy lifting.
				// There are still extreme circumstances where unconditional branches
				// using other registers as displacement could cause issues (think about it).
				// (I think that this last statement is actually invalid)

				// Potential fix, check for specific circumstances:
				// lea reg1, [rip]
				// add reg1, reg2 
				// unconditional branch [reg1]
				// Translate such a branch so that an absolute address jumping
				// to the original page is calculated. Handle bad branches in the
				// page fault handler.

				memcpy(mpAddress, disassembler->address, instruction->length);
				return true;
			}
		}

		if (!TranslateRelativeInstruction(hook, disassembler))
			return false;
	}
	else
	{
		memcpy(mpAddress, disassembler->address, instruction->length);
	}

	return true;
}

bool ParseAndTranslate(PFHook* hook, UINT8* address, bool parseBranch)
{
	Disassembler disassembler;
	if (ZYAN_FAILED(InitializeDisassembler(&disassembler,
		ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64, address)))
	{
		return false;
	}

	for (; (disassembler.address >= hook->OriginalPageInstructions()) && 
		(disassembler.address < hook->OriginalPageEnd());
		NextInstruction(&disassembler))
	{
		if (ZYAN_FAILED(Disassemble(&disassembler, 
			ZYDIS_MAX_INSTRUCTION_LENGTH)))
		{
			return false;
		}

		ZydisDecodedInstruction* instruction = &disassembler.instruction;

		if ((disassembler.address + instruction->length) < hook->OriginalPage())
		{
			continue;
		}

		// Don't make passes over analyzed instructions
		if (!VerifyInstruction(hook->OriginalToNew(
			disassembler.address), instruction->length))
		{
			break;
		}

		// Maybe move this above the ParseAndTranslateSingleInstruction for accurate branch parsing
		// I think that this will require single-step exceptions
		// (This requires this check: (instruction->meta.branch_type != ZYDIS_BRANCH_TYPE_NONE && !parseBranch))
		if (instruction->mnemonic == ZYDIS_MNEMONIC_INT3)
		{
			break;
		}

		if (!ParseAndTranslateSingleInstruction(&disassembler, hook, parseBranch))
			return false;
	}

	if (disassembler.address >= hook->OriginalPageEnd())
	{
		PlaceAbsoluteJump(hook->OriginalToNew(disassembler.address), 
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

	return ParseAndTranslate(tempPFHook, tempPFHook->mOriginalAddress, false);
}

void RemoveHook(void* address)
{
	UNREFERENCED_PARAMETER(address);
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

	DWORD oldProtect = 0;
	VirtualProtect(&MessageBoxA, 1, PAGE_READWRITE, &oldProtect);

	MessageBoxA(nullptr, "Test", nullptr, MB_ICONWARNING);

	VirtualProtect(&MessageBoxA, 1, oldProtect, &oldProtect);

	//UINT8* messageBoxA = tempPFHook->OriginalToNew(&MessageBoxA);
	//((decltype(MessageBoxA)*)(messageBoxA))(nullptr, "Test", nullptr, MB_ICONWARNING);

	UninitializePFH();

	return 0;
}