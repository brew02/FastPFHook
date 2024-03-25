#pragma once
#include "hook.h"

ZyanStatus PlaceAbsoluteInstruction(PFHook* hook, 
	UINT64 rip, Disassembler* disassembler);
bool TranslateRelativeInstruction(PFHook* hook, Disassembler* disassembler);
bool ParseAndTranslateSingleInstruction(Disassembler* disassembler, PFHook* hook, bool parseBranch);
bool ParseAndTranslateSafe(PFHook* hook, void* address, bool parseBranch);