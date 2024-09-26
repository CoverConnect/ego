package disassembler

import (
	"flag"
	"fmt"

	"github.com/go-delve/delve/pkg/proc"
)

var (
	// TODO need find a way to sync this value between injector and here
	numOfCall = flag.Int("numOfCall", 2, "number of call instruction inserted at function start")
	limitCall = *numOfCall + 5
)

// GetMutableInterval will return a interval [mutStart, mutEnd), where all instruction
// in this interval is mutable
// NOTE: mutStart is inclusive, mutEnd is exclusive, namely [mutStart, mutEnd)
func GetMutableInterval(fInsts []proc.AsmInstruction) (mutStart, mutEnd uint64, err error) {

	var startIdx, endIdx int
	if startIdx, endIdx, err = findNContiguousSameCall(fInsts, *numOfCall, limitCall); err != nil {
		return 0, 0, err
	}

	mutStart = (fInsts[startIdx].Loc.PC)
	mutEnd = (fInsts[endIdx].Loc.PC) + uint64(fInsts[endIdx].Size)
	return mutStart, mutEnd, nil
}

// find n contiguous call instruction, in range [startIdx, endIdx], where
// no more than `limit` call exist in `instructions[:endIdx]`
// NOTE: we expect n >= 2, otherwise we cannot distinguish the inserted call and defer call
// TODO:
//
//	use dwarf to find the function name using PC, so that we can directly identify the
//	call to inserted function
func findNContiguousSameCall(instructions []proc.AsmInstruction, n, limit int) (startIdx, endIdx int, err error) {

	if n < 2 {
		return -1, -1, fmt.Errorf("insert at least two call")
	}
	cnt := 0
	prev := uintptr(0)
	callCnt := 0
	for idx, instruction := range instructions {
		if callCnt >= limit {
			break
		}
		x86Inst := instruction.Inst.(*x86Inst)

		if IsDirectCall(x86Inst) {
			callCnt++

			PC, err := GetDestPC(instruction)
			if err != nil {
				prev = uintptr(0)
				cnt = 0
				continue
			}
			if prev != PC {
				prev = PC
				cnt = 1
				startIdx = idx
			} else {
				cnt++
			}

			if cnt == n {
				return startIdx, idx, nil
			}
		}
	}
	return startIdx, endIdx, fmt.Errorf("cannot find %d contiguous call before see %d call", n, limit)
}
