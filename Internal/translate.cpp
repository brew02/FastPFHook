#include "translate.h"

// Remove rip and just use disassembler
// We need to deal with double branches (place breakpoints on them properly)
// Ex.
// jcc (2 bytes)
// jmp (x bytes)
//
ZyanStatus PlaceAbsoluteInstruction(PFHook* hook, 
	UINT64 rip, Disassembler* disassembler)
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

		ZydisOperandType type = ZYDIS_OPERAND_TYPE_UNUSED;
		UINT8* branchAddress = GetBranchAddress(disassembler, reinterpret_cast<UINT8*>(rip), &type);
		if (!branchAddress)
			return false;

		UINT8 instructionLength = GetInstructionLengthAtAddress(branchAddress);
		if (!instructionLength)
			return ZYAN_STATUS_FAILED;

		// Add a new jump for all instructions that leave our page
		// that are instead redirected to an exit gate.
		// This exit gate will lock dec byte ptr [rax], where rax contains the threadCount 
		// before leaving the page as normal.
		// It may perform other operations in the future as well.

		if (((branchAddress + instructionLength) >= hook->OriginalPage() &&
			branchAddress < hook->OriginalPageEnd()))
		{
			if (!hook->PlaceAbsoluteJump(reinterpret_cast<UINT64>(hook->OriginalToNew(branchAddress))))
				return ZYAN_STATUS_FAILED;
		}
		else
		{
			if (type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
			{
				if (!hook->PlaceAbsoluteJump(reinterpret_cast<UINT64>(branchAddress)))
					return ZYAN_STATUS_FAILED;
			}
			else
			{
				if (!hook->PlaceAbsoluteJump(reinterpret_cast<UINT64>(branchAddress)))
					return ZYAN_STATUS_FAILED;
			}
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

		// must be changed (use breakpoints)
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

			hook->InsertTranslation(PFHook::Translation{ disassembler->address, 
				static_cast<uint32_t>(hook->mRelocCursor - hook->mNewPages) });
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
			UINT8* branchAddress = GetBranchAddress(disassembler, disassembler->address + instruction->length, &type);
			if (!branchAddress)
				return false;

			if ((branchAddress >= hook->OriginalPageInstructions() &&
				branchAddress < hook->OriginalPageEnd()))
			{
				UINT8 length = GetInstructionLengthAtAddress(branchAddress);
				if (!length ||
					(branchAddress + length) < hook->OriginalPage() ||
					!parseBranch)
				{
					return false;
				}

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

bool ParseAndTranslate(PFHook* hook, void* address, bool parseBranch)
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

bool ParseAndTranslateSafe(PFHook* hook, void* address, bool parseBranch)
{
	hook->LockWrites();
	bool status = ParseAndTranslate(hook, address, parseBranch);
	hook->UnlockWrites();

	return status;
}