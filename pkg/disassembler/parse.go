package disassembler

import "github.com/backman-git/delve/pkg/proc"

func GetEpilogue(instructions []proc.AsmInstruction) []proc.AsmInstruction {
	_, epilogueStart, ok := findFirstJmp(instructions, 0)
	if !ok {
		return nil
	}

	morestackCallIndex, _, ok := findMorestackCall(instructions, epilogueStart)
	if !ok {
		return nil
	}

	epilogueEnd, ok := findJmpToStart(instructions, morestackCallIndex)
	if !ok {
		return nil
	}

	return instructions[epilogueStart:epilogueEnd]
}
