#pragma once
#include <Windows.h>

#include <Zydis/Zydis.h>

struct Disassembler
{
	ZydisDecoder decoder;
	ZydisDecoderContext context;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	UINT8* address;
};

ZyanStatus InitializeDisassembler(Disassembler* disassembler,
	ZydisMachineMode machineMode, ZydisStackWidth stackWidth, void* address);

ZydisRegister GetUnusedGPRegister(ZydisDecodedInstruction* instruction, ZydisDecodedOperand* operands);
UINT8* GetBranchAddress(Disassembler* disassembler, UINT8* newRIP, ZydisOperandType* type);
UINT8 GetInstructionLengthAtAddress(void* address);

void PlaceRelativeJump(void* destination, INT32 offset);
void PlaceAbsoluteJump(void* destination, UINT64 address);
void PlaceManualReturnAddress(void* destination, UINT64 returnAddress);

__forceinline void NextInstruction(Disassembler* disassembler)
{
	disassembler->address += disassembler->instruction.length;
}

__forceinline ZyanStatus Disassemble(Disassembler* disassembler, UINT_PTR length)
{
	return ZydisDecoderDecodeFull(&disassembler->decoder, disassembler->address,
		length, &disassembler->instruction, disassembler->operands);
}

#define RVA(base, address) reinterpret_cast<UINT64>(base) - reinterpret_cast<UINT64>(address)

#define GP_REGISTER_COUNT ((ZYDIS_REGISTER_R15 - ZYDIS_REGISTER_RAX) + 1)
#define JMP_SIZE_32 5
#define JMP_SIZE_ABS 14
#define MANUAL_RET_SIZE 13