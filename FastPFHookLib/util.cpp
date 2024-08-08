#include "util.h"

ZyanStatus InitializeDisassembler(Disassembler* disassembler,
	ZydisMachineMode machineMode, ZydisStackWidth stackWidth, void* address)
{
	ZeroMemory(disassembler, sizeof(Disassembler));
	disassembler->address = reinterpret_cast<UINT8*>(address);
	return ZydisDecoderInit(&disassembler->decoder, machineMode, stackWidth);
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

// Change this so that we don't supply our own RIP (just use the originalRIP)
// We need to handle the two other cases properly as well
UINT8* GetBranchAddress(Disassembler* disassembler, ZydisOperandType* type)
{
	UINT8* originalRIP = disassembler->address + disassembler->instruction.length;

	for (int i = 0; i < disassembler->instruction.operand_count_visible; i++)
	{
		ZydisDecodedOperand* operand = &disassembler->operands[i];
		if (operand->type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
			operand->imm.is_relative)
		{
			*type = operand->type;
			return originalRIP + operand->imm.value.s;
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

UINT8 GetInstructionLengthAtAddress(void* address)
{
	Disassembler disassembler;
	if (ZYAN_FAILED(InitializeDisassembler(
		&disassembler, ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64, address)))
	{
		return 0;
	}

	if (ZYAN_FAILED(ZydisDecoderDecodeInstruction(
		&disassembler.decoder, nullptr,
		address, ZYDIS_MAX_INSTRUCTION_LENGTH, 
		&disassembler.instruction)))
	{
		return 0;
	}

	return disassembler.instruction.length;
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