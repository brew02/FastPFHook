#include <Windows.h>
#include <stdio.h>
#include <intrin.h>

#include <Zydis/Zydis.h>

// Add credits to MinHook author and SMAP Btbd

#define PAGE_SIZE 0x1000
#define PAGE_ALIGN(address) (UINT_PTR)(address) & (~0xFFFllu)
#define INITIAL_HOOK_SIZE 2 * PAGE_SIZE
#define JMP_SIZE_32 5

#define GP_REGISTER_COUNT (ZYDIS_REGISTER_R15 - ZYDIS_REGISTER_RAX) + 1

struct HookData
{
	UINT8* modifiedPagesStart;
	UINT8* modifiedPagesEnd;
	UINT8* hookAddress;
	UINT8* hookPage;
	UINT8* instructionStart;
	UINT8* relocationCursor;
};

void* gExceptionHandlerHandle = nullptr;
HookData singleHook;

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

void PlaceRelativeJump(void* destination, UINT32 offset)
{
	UINT8 instruction[JMP_SIZE_32] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
	*(UINT32*)(&instruction[1]) = offset;

	memcpy(destination, instruction, JMP_SIZE_32);
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

bool PlaceAbsoluteInstruction(UINT8** relocationCursor, ZydisRegister reg, UINT64 rip,
	ZydisDecodedInstruction* instruction, ZydisDecodedOperand* operands)
{
	UINT8 buffer[ZYDIS_MAX_INSTRUCTION_LENGTH];
	ZyanUSize length = 0;
	ZydisEncoderRequest request;
	ZeroMemory(&request, sizeof(request));

	request.mnemonic = ZYDIS_MNEMONIC_PUSH;
	request.machine_mode = instruction->machine_mode;
	request.operand_count = 1;
	request.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
	request.operands[0].reg.value = reg;

	if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&request, buffer, &length)))
		return false;

	memcpy(*relocationCursor, buffer, length);
	*relocationCursor += length;

	length = 0;
	ZeroMemory(&request, sizeof(request));
	request.mnemonic = ZYDIS_MNEMONIC_MOV;
	request.machine_mode = instruction->machine_mode;
	request.operand_count = 2;
	request.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
	request.operands[0].reg.value = reg;
	request.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
	request.operands[1].imm.u = rip;

	if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&request, buffer, &length)))
		return false;

	memcpy(*relocationCursor, buffer, length);
	*relocationCursor += length;

	length = 0;
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

		if (operand->type == ZYDIS_OPERAND_TYPE_IMMEDIATE
			&& request.branch_type != ZYDIS_BRANCH_TYPE_NONE)
		{
			operand->type = ZYDIS_OPERAND_TYPE_MEMORY;
			operand->mem.base = reg;
			operand->mem.displacement = operand->imm.s;
			operand->imm.s = 0;
			operand->mem.size = 8;

			request.branch_type = ZYDIS_BRANCH_TYPE_NONE;
			request.branch_width = ZYDIS_BRANCH_WIDTH_NONE;
			break;
		}
	}

	if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&request, buffer, &length)))
		return false;

	memcpy(*relocationCursor, buffer, length);
	*relocationCursor += length;

	length = 0;
	ZeroMemory(&request, sizeof(request));

	request.mnemonic = ZYDIS_MNEMONIC_POP;
	request.machine_mode = instruction->machine_mode;
	request.operand_count = 1;
	request.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
	request.operands[0].reg.value = reg;

	if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&request, buffer, &length)))
		return false;

	memcpy(*relocationCursor, buffer, length);
	*relocationCursor += length;

	return true;
}

bool TranslateRelativeInstruction(HookData* hookData, UINT64 currentOffset,
	ZydisDecodedInstruction* instruction, ZydisDecodedOperand* operands)
{
	UINT8* currentOriginalAddress = (UINT8*)(PAGE_ALIGN(hookData->hookAddress)) + currentOffset;

	UINT8* currentModifiedAddress = hookData->modifiedPagesStart + currentOffset;
	UINT8* nextModifiedAddress = currentModifiedAddress + instruction->length;

	UINT32 relocationRVA = (UINT32)(hookData->relocationCursor - nextModifiedAddress);
	// Care must be taken for relative unconditional branches as well
	// Certain branches of this variety in obfuscated code will branch
	// between instruction boundaries. 
	// To combat this we simply check to see if the instruction that
	// we parse is any different from the original page. 

	if (instruction->length < JMP_SIZE_32)
	{
		// This will require a similar operation as to what is listed
		// below, but we will need to analyze two instructions and place
		// them at relocation cursor.
	}
	else
	{
		// Maybe replace with proper NOP slide
		memset(currentModifiedAddress, 0x90, instruction->length);

		PlaceRelativeJump(nextModifiedAddress, relocationRVA);
		ZydisRegister reg = GetUnusedGPRegister(instruction, operands);
		if (reg == ZYDIS_REGISTER_INVALID)
			return false;


		// NOP length of instruction at modifiedPage offset
		// Create a jmp to relocationCursor
		// Fix the instruction and place the instruction at relocation cursor
		// Create another jmp to go to the instruction after our other jmp
	}

	return true;
}

/*
* @param hookAddress: The address of the something (TODO: change parameter names)
*/
bool ParseAndTranslate(HookData* hookData)
{
	ZydisDecoder decoder;
	ZydisDecoderContext decoderContext;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	ZydisFormatter formatter;

	ZeroMemory(&decoder, sizeof(decoder));
	ZeroMemory(&decoderContext, sizeof(decoderContext));
	ZeroMemory(&instruction, sizeof(instruction));
	ZeroMemory(operands, sizeof(operands));
	ZeroMemory(&formatter, sizeof(formatter));

	if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
	{
		return false;
	}

	if (ZYAN_FAILED(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL)))
	{
		return false;
	}


	for (UINT64 currentAddress = (UINT64)hookData->hookAddress,
		currentOffset = (currentAddress - PAGE_ALIGN(currentAddress));
		(currentOffset >= 0) && (currentOffset < PAGE_SIZE);
		currentAddress += instruction.length,
		currentOffset += instruction.length)
	{
		if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, &decoderContext,
			(const void*)currentAddress, ZYDIS_MAX_INSTRUCTION_LENGTH, &instruction)))
		{
			return false;
		}

		if (!ZYAN_SUCCESS(ZydisDecoderDecodeOperands(&decoder, &decoderContext,
			&instruction, operands, instruction.operand_count)))
		{
			return false;
		}

		// JCCs can be unreliable to track, let the hardware handle it
		// We may need to track eflags and deal with jccs
		// We could put breakpoints on the jccs
		// We can find out if an instruction jumps between a boundary by checking if the
		// disassembled instructions are equal to each other and it is NOT one of our jmps
		if (instruction.meta.category == ZYDIS_CATEGORY_COND_BR)
			continue;

		if (instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE)
		{
			char buffer[256];
			if (ZYAN_FAILED(ZydisFormatterFormatInstruction(&formatter, &instruction,
				operands, instruction.operand_count_visible, buffer, sizeof(buffer),
				ZYDIS_RUNTIME_ADDRESS_NONE, ZYAN_NULL)))
			{
				continue;
			}

			printf("%s\n", buffer);

			ZydisEncoderRequest request;
			ZeroMemory(&request, sizeof(request));

			if (ZYAN_FAILED(ZydisEncoderDecodedInstructionToEncoderRequest(&instruction, operands, instruction.operand_count_visible, &request)))
			{
				printf("Failed to convert decoded instruction to encoder request!\n");
				continue;
			}

			for (int i = 0; i < request.operand_count; i++)
			{
				ZydisEncoderOperand* operand = &request.operands[i];
				if (operand->type == ZYDIS_OPERAND_TYPE_MEMORY &&
					operand->mem.base == ZYDIS_REGISTER_RIP)
				{
					operand->mem.base = ZYDIS_REGISTER_RAX;
				}

				if (operand->type == ZYDIS_OPERAND_TYPE_IMMEDIATE
					&& request.branch_type != ZYDIS_BRANCH_TYPE_NONE)
				{
					operand->type = ZYDIS_OPERAND_TYPE_MEMORY;
					operand->mem.base = ZYDIS_REGISTER_RAX;
					operand->mem.displacement = operand->imm.s;
					operand->imm.s = 0;
					operand->mem.size = 8;

					request.branch_type = ZYDIS_BRANCH_TYPE_NONE;
					request.branch_width = ZYDIS_BRANCH_WIDTH_NONE;
				}
			}

			UINT8 encodedInstruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
			ZyanUSize length = sizeof(encodedInstruction);
			ZyanStatus status = ZydisEncoderEncodeInstruction(&request, encodedInstruction, &length);
			if (ZYAN_FAILED(status))
			{
				printf("Failed to re-encode this instruction! 0x%lx\n", ZYAN_STATUS_CODE(status));
				continue;
			}

			ZydisDisassembledInstruction instr;
			if (ZYAN_FAILED(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_RUNTIME_ADDRESS_NONE, encodedInstruction, length, &instr)))
			{
				printf("Failed to re-disassemble the encoded instruction!\n");
				continue;
			}

			printf("\tfixed -> %s\n", instr.text);

			printf("\n");
		}
		else
		{
			//memcpy(hookData->modifiedPagesStart + currentOffset, (void*)currentAddress, instruction.length);
		}
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
	singleHook.hookPage = (UINT8*)(PAGE_ALIGN(address));
	singleHook.modifiedPagesStart = hookAddress;
	singleHook.modifiedPagesEnd = hookAddress + INITIAL_HOOK_SIZE;

	// +2 and +1 to align on a 16 byte boundary
	singleHook.relocationCursor = hookAddress + PAGE_SIZE + ZYDIS_MAX_INSTRUCTION_LENGTH * 2 + 2;
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
	/*if (!InitializePFH())
		return -1;

	InstallHook(&MessageBoxA);

	UninitializePFH();*/

	return 0;
}