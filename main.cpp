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

struct HookData
{
	UINT8* modifiedPagesStart;
	UINT8* modifiedPagesEnd;
	UINT8* hookAddress;
	UINT8* hookPageStart;
	UINT8* hookPageEnd;
	UINT8* instructionStart;
	UINT8* relocationCursor;
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

long __stdcall ExceptionHandler(EXCEPTION_POINTERS* exceptionInfo)
{
	EXCEPTION_RECORD* exceptionRecord = exceptionInfo->ExceptionRecord;
	CONTEXT* contextRecord = exceptionInfo->ContextRecord;

	if (exceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{

	}
	else if (exceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
	{

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
	UINT8* target = (UINT8*)destination;

	// push lower half
	target[0] = 0x68;
	*(UINT32*)(&target[1]) = (UINT32)returnAddress;

	// mov dword ptr [rsp + 4], upper half of address
	target[5] = 0xc7;
	target[6] = 0x44;
	target[7] = 0x24;
	target[8] = 0x04;
	*(UINT32*)(&target[9]) = (UINT32)(returnAddress >> 32);
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

ZyanStatus PlaceAbsoluteInstruction(UINT8** relocationCursor, UINT64 rip,
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

	// We will also need to perform checks to see if the location
	// lands within or outside our page for all types of branches.
	if (instruction->meta.branch_type != ZYDIS_BRANCH_TYPE_NONE)
	{
		if (instruction->meta.category == ZYDIS_CATEGORY_CALL)
		{
			PlaceManualReturnAddress(*relocationCursor, (UINT64)(*relocationCursor + MANUAL_RET_SIZE + JMP_SIZE_ABS));
			*relocationCursor += MANUAL_RET_SIZE;
		}

		PlaceAbsoluteJump(*relocationCursor, rip + operands[0].imm.value.u);
		*relocationCursor += JMP_SIZE_ABS;

		return true;
	}

	request.mnemonic = ZYDIS_MNEMONIC_PUSH;
	request.machine_mode = instruction->machine_mode;
	request.operand_count = 1;
	request.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
	request.operands[0].reg.value = reg;

	status = ZydisEncoderEncodeInstruction(&request, buffer, &length);
	if (ZYAN_FAILED(status))
		return status;

	memcpy(*relocationCursor, buffer, length);
	*relocationCursor += length;

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

	memcpy(*relocationCursor, buffer, length);
	*relocationCursor += length;

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

	memcpy(*relocationCursor, buffer, length);
	*relocationCursor += length;

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

	memcpy(*relocationCursor, buffer, length);
	*relocationCursor += length;

	return true;
}

// Need to add extending capabilities for when relocationCursor crosses outside
// of the modifiedPage boundaries.

bool TranslateRelativeInstruction(HookData* hookData, Disassembler* disassembler)
{
	ZydisDecodedInstruction* instruction = &disassembler->instruction;
	ZydisDecodedOperand* operands = disassembler->operands;

	UINT8* currentModifiedAddress = hookData->modifiedPagesStart + 
		(disassembler->address - hookData->hookPageStart);

	UINT8* nextModifiedAddress = currentModifiedAddress + instruction->length;

	UINT32 relocationRVA = (UINT32)(hookData->relocationCursor - (currentModifiedAddress + JMP_SIZE_32));
	UINT8 totalLength = instruction->length;
	// Care must be taken for relative unconditional branches as well
	// Certain branches of this variety in obfuscated code will branch
	// between instruction boundaries. 
	// To combat this we simply check to see if the instruction that
	// we parse is any different from the original page. 

	while (true)
	{
		if (instruction->attributes & ZYDIS_ATTRIB_IS_RELATIVE)
		{
			if (ZYAN_FAILED(PlaceAbsoluteInstruction(&hookData->relocationCursor,
				(UINT64)disassembler->address + instruction->length, instruction, operands)))
			{
				return false;
			}
		}
		else
		{
			memcpy(hookData->relocationCursor, disassembler->address, instruction->length);
			hookData->relocationCursor += instruction->length;
		}

		// This needs to change to account for jumping back to the page following
		// the hooked page.
		// 1) totalLength must be incremented properly
		// 2) We must craft an absolute jump that lands on the NEXT instruction
		// of the following page.
		if ((disassembler->address + instruction->length) < hookData->hookPageStart ||
			(disassembler->address + instruction->length) >= hookData->hookPageEnd)
		{
			break;
		}

		if (totalLength < JMP_SIZE_32)
		{
			NextInstruction(disassembler);
			if (ZYAN_FAILED(Disassemble(disassembler, ZYDIS_MAX_INSTRUCTION_LENGTH)))
				return false;
		}
		else
		{
			break;
		}

		totalLength += instruction->length;
	}

	PlaceRelativeJump(currentModifiedAddress, (INT32)relocationRVA);
	ZydisEncoderNopFill(currentModifiedAddress + JMP_SIZE_32, totalLength - JMP_SIZE_32);

	PlaceRelativeJump(hookData->relocationCursor, (INT32)(nextModifiedAddress - (hookData->relocationCursor + JMP_SIZE_32)));
	hookData->relocationCursor += JMP_SIZE_32;

	// NOP length of instruction at modifiedPage offset
	// Create a jmp to relocationCursor
	// Fix the instruction and place the instruction at relocation cursor
	// Create another jmp to go to the instruction after our other jmp

	return true;
}

/*
* @param hookAddress: The address of the something (TODO: change parameter names)
*/
bool ParseAndTranslate(HookData* hookData)
{
	Disassembler disassembler;
	if (ZYAN_FAILED(InitializeDisassembler(&disassembler,
		ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64, hookData->hookAddress)))
	{
		return false;
	}

	for (; (disassembler.address >= hookData->hookPageStart) && 
		(disassembler.address < hookData->hookPageEnd);
		NextInstruction(&disassembler))
	{
		if (ZYAN_FAILED(Disassemble(&disassembler, 
			ZYDIS_MAX_INSTRUCTION_LENGTH)))
		{
			return false;
		}

		ZydisDecodedInstruction* instruction = &disassembler.instruction;

		// JCCs can be unreliable to track, let the hardware handle it
		// We may need to track eflags and deal with jccs
		// We could put breakpoints on the jccs
		// We can find out if an instruction jumps between a boundary by checking if the
		// disassembled instructions are equal to each other and it is NOT one of our jmps
		/*if (instruction.meta.category == ZYDIS_CATEGORY_COND_BR)
			continue;*/

		if (instruction->attributes & ZYDIS_ATTRIB_IS_RELATIVE &&
			instruction->meta.category != ZYDIS_CATEGORY_COND_BR)
		{
			if (!TranslateRelativeInstruction(hookData, &disassembler))
				return false;
		}
		else
		{
			memcpy(hookData->modifiedPagesStart + (disassembler.address - 
				hookData->hookPageStart), disassembler.address, instruction->length);
		}

		// This needs to change
		if (instruction->mnemonic == ZYDIS_MNEMONIC_RET)
			break;
	}

	return true;
}

bool InstallHook(void* address)
{
	UINT8* hookAddress = (UINT8*)VirtualAlloc(nullptr, INITIAL_HOOK_SIZE,
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!hookAddress)
		return false;

	memset(hookAddress, 0xCC, INITIAL_HOOK_SIZE);

	singleHook.hookAddress = (UINT8*)address;
	singleHook.hookPageStart = (UINT8*)(PAGE_ALIGN(address));
	singleHook.hookPageEnd = singleHook.hookPageStart + PAGE_SIZE;
	singleHook.modifiedPagesStart = hookAddress;
	singleHook.modifiedPagesEnd = hookAddress + INITIAL_HOOK_SIZE;

	// +4 and +1 to align on a 16 byte boundary
	singleHook.relocationCursor = hookAddress + PAGE_SIZE + ZYDIS_MAX_INSTRUCTION_LENGTH * 2 + JMP_SIZE_ABS + 4;
	singleHook.instructionStart = hookAddress + ZYDIS_MAX_INSTRUCTION_LENGTH + 1;

	return ParseAndTranslate(&singleHook);
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

	UINT8* messageBoxA = singleHook.modifiedPagesStart + (singleHook.hookAddress - singleHook.hookPageStart);
	((decltype(MessageBoxA)*)(messageBoxA))(nullptr, "Test", nullptr, MB_ICONWARNING);

	UninitializePFH();

	return 0;
}