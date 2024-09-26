package disassembler

import (
	"fmt"
	"log"
	"strings"

	"github.com/go-delve/delve/pkg/proc"
	"golang.org/x/arch/x86/x86asm"
)

type x86Inst x86asm.Inst

func (inst *x86Inst) OpcodeEquals(op uint64) bool {
	if inst == nil {
		return false
	}
	return uint64(inst.Op) == op
}
func (inst *x86Inst) Text(flavour proc.AssemblyFlavour, pc uint64, symLookup func(uint64) (string, uint64)) string {
	if inst == nil {
		return "?"
	}

	var text string

	switch flavour {
	case proc.GNUFlavour:
		text = x86asm.GNUSyntax(x86asm.Inst(*inst), pc, symLookup)
	case proc.GoFlavour:
		text = x86asm.GoSyntax(x86asm.Inst(*inst), pc, symLookup)
	case proc.IntelFlavour:
		fallthrough
	default:
		text = x86asm.IntelSyntax(x86asm.Inst(*inst), pc, symLookup)
	}

	return text
}

func IsDirectCall(i *x86Inst) bool {
	if i.Op != x86asm.CALL {
		return false
	}
	return isArgRel(i)
}

func isArgRel(i *x86Inst) bool {
	_, ok := i.Args[0].(x86asm.Rel)
	return ok
}

func IsDirectJump(inst *x86Inst) bool {

	op := inst.Op

	switch op {
	case x86asm.JA,
		x86asm.JAE,
		x86asm.JB,
		x86asm.JBE,
		x86asm.JCXZ,
		x86asm.JE,
		x86asm.JECXZ,
		x86asm.JG,
		x86asm.JGE,
		x86asm.JL,
		x86asm.JLE,
		x86asm.JMP,
		x86asm.JNE,
		x86asm.JNO,
		x86asm.JNP,
		x86asm.JNS,
		x86asm.JO,
		x86asm.JP,
		x86asm.JRCXZ,
		x86asm.JS:
		return isArgRel(inst)
	}
	return false
}

func decodeOne(bytes []byte) (proc.AsmInstruction, error) {

	inst, err := x86asm.Decode(bytes, 64)
	if err != nil {
		return proc.AsmInstruction{}, fmt.Errorf("decode error: %v", err)
	}

	instKind := proc.OtherInstruction

	switch inst.Op {
	case x86asm.JMP, x86asm.LJMP:
		instKind = proc.JmpInstruction
	case x86asm.CALL, x86asm.LCALL:
		instKind = proc.CallInstruction
	case x86asm.RET, x86asm.LRET:
		instKind = proc.RetInstruction
	case x86asm.INT:
		instKind = proc.HardBreakInstruction
	}

	return proc.AsmInstruction{
		Inst: (*x86Inst)(&inst),
		Size: inst.Len,
		Loc:  proc.Location{},
		Kind: instKind,
	}, nil
}

func Decode(startPC uint64, endPC uint64) ([]proc.AsmInstruction, error) {

	funcLen := endPC - startPC
	funcBytes := MakeSliceFromPointer(startPC, int(funcLen))

	instructions, err := decode(funcBytes, startPC)
	if err != nil {
		return nil, err
	}

	return instructions, nil
}

func decode(funcAsm []byte, startPC uint64) ([]proc.AsmInstruction, error) {
	var instructions []proc.AsmInstruction

	funcLen := len(funcAsm)
	offset := uintptr(0)

	for int(offset) < funcLen {
		inst, err := decodeOne(funcAsm[offset:])
		if err != nil {
			return nil, fmt.Errorf("decode: inst:%x offset: %d, startpc: %x", funcAsm, offset, startPC)
		}

		inst.Loc.PC = (startPC) + uint64(offset)
		//inst.Offset = offset

		instructions = append(instructions, inst)
		offset += uintptr(inst.Size)
	}
	return instructions, nil
}

func GetDestPC(inst proc.AsmInstruction) (uintptr, error) {

	x86Inst := inst.Inst.(*x86Inst)

	if !IsDirectCall(x86Inst) && !IsDirectJump(x86Inst) {
		return 0, fmt.Errorf("Can't get Desc PC from %v", inst)
	}

	relDest := x86Inst.Args[0].(x86asm.Rel)
	return uintptr(int64(relDest) + int64(inst.Loc.PC) + int64(inst.Size)), nil
}

func GetFirstInstructionWithCond(instructions []proc.AsmInstruction, filter func(inst *x86Inst) bool) (proc.AsmInstruction, int, bool) {

	for idx, inst := range instructions {
		if filter(inst.Inst.(*x86Inst)) {
			return inst, idx, true
		}
	}
	return proc.AsmInstruction{}, 0, false
}

func findFirstJmp(instructions []proc.AsmInstruction, startIndex int) (jmpIndex int, jmpDestIndex int, ok bool) {
	for i := startIndex; i < len(instructions); i++ {
		jmp, jmpIndex, ok := GetFirstInstructionWithCond(instructions[i:], IsDirectJump)
		if !ok {
			log.Println("No Jump in code segment")
			return 0, 0, false
		}
		jmpIndex += i
		jmpDest, err := GetDestPC(jmp)
		if err != nil {
			log.Printf("Can't find first jmp dest PC. inst pc: %x\n", jmp.Loc.PC)
			return 0, 0, false
		}

		destFound := false
		for j, inst := range instructions {
			if uintptr(inst.Loc.PC) == jmpDest {
				destFound = true
				jmpDestIndex = j
				break
			}
		}
		if !destFound {
			log.Printf("Can't find first jmp dest. jmp PC: %x, dest PC: %x\n ", jmp.Loc.PC, jmpDest)
			return 0, 0, false
		}

		if jmpDestIndex == jmpIndex+1 {
			continue
		}

		return jmpIndex, jmpDestIndex, true
	}

	return 0, 0, false
}

func findMorestackCall(instructions []proc.AsmInstruction, startIndex int) (callIndex int, callDest uintptr, ok bool) {
	call, callIndex, ok := GetFirstInstructionWithCond(instructions[startIndex:], IsDirectCall)
	if !ok {
		log.Printf("No Call in epilogue")
		return 0, 0, false
	}
	callIndex += startIndex

	callDest, err := GetDestPC(call)
	if err != nil {
		log.Printf("No Dest PC in morestackCall")
		return 0, 0, false
	}

	return callIndex, callDest, true
}

func findJmpToStart(instructions []proc.AsmInstruction, epilogueStart int) (jmpIndex int, ok bool) {
	jmpIndex, jmpDestIndex, ok := findFirstJmp(instructions, epilogueStart)
	if !ok || jmpDestIndex != 0 {
		return 0, false
	}
	return jmpIndex, true
}

// read from internal mem
func GetOriginalRegBackup(epiInsts []proc.AsmInstruction) (regBackup []byte, regRestore []byte) {

	for _, inst := range epiInsts {
		x86Inst := inst.Inst.(*x86Inst)

		if !strings.HasPrefix(x86Inst.Op.String(), "MOV") {
			continue
		}

		instBytes := MakeSliceFromPointer((inst.Loc.PC), inst.Size)
		_, restore := x86Inst.Args[0].(x86asm.Reg)

		if restore {
			regRestore = append(regRestore, instBytes...)

		} else {
			regBackup = append(regBackup, instBytes...)
		}
	}
	return regBackup, regRestore
}
