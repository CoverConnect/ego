package disassembler

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"testing"

	"github.com/backman-git/delve/pkg/proc"
)

var code = []byte{
	0x49, 0x3b, 0x66, 0x10,
	0x76, 0x2a,
	0x48, 0x83, 0xec, 0x18,
	0x48, 0x89, 0x6c, 0x24, 0x10,
	0x48, 0x8d, 0x6c, 0x24, 0x10,
	0x48, 0x8b, 0x0d, 0x85, 0x9a, 0x0a, 0x00,
	0x48, 0x89, 0xc3,
	0x48, 0x89, 0xc8,
	0xe8, 0x7a, 0xf9, 0xff, 0xff,
	0x48, 0x8b, 0x6c, 0x24, 0x10,
	0x48, 0x83, 0xc4, 0x18,
	0xc3,
	0x48, 0x89, 0x44, 0x24, 0x08,
	0xe8, 0xa6, 0x96, 0xfd, 0xff,
	0x48, 0x8b, 0x44, 0x24, 0x08,
	0x90,
	0xeb, 0xbe,
}

/*
TEXT main.Target(SB) /home/vagrant/nirmata/binfo/testBin/main.go

	func Target(n int) int {
	  0x481840              493b6610                CMPQ 0x10(R14), SP
	  0x481844              762a                    JBE 0x481870
	  0x481846              4883ec18                SUBQ $0x18, SP
	  0x48184a              48896c2410              MOVQ BP, 0x10(SP)
	  0x48184f              488d6c2410              LEAQ 0x10(SP), BP
	        return rand.Intn(n)
	  0x481854              488b0d859a0a00          MOVQ math/rand.globalRand(SB), CX

func Intn(n int) int { return globalRand.Intn(n) }

	0x48185b              4889c3                  MOVQ AX, BX
	0x48185e              4889c8                  MOVQ CX, AX
	0x481861              e87af9ffff              CALL math/rand.(*Rand).Intn(SB)
	      return rand.Intn(n)
	0x481866              488b6c2410              MOVQ 0x10(SP), BP
	0x48186b              4883c418                ADDQ $0x18, SP
	0x48186f              c3                      RET

	func Target(n int) int {
	  0x481870              4889442408              MOVQ AX, 0x8(SP)
	  0x481875              e8a696fdff              CALL runtime.morestack_noctxt.abi0(SB)
	  0x48187a              488b442408              MOVQ 0x8(SP), AX
	  0x48187f              90                      NOPL
	  0x481880              ebbe                    JMP main.Target(SB)
*/

var bi *proc.BinaryInfo

func TestMain(m *testing.M) {
	bi = proc.NewBinaryInfo(runtime.GOOS, runtime.GOARCH)
	err := bi.LoadBinaryInfo("/home/vagrant/nirmata/binfo/testBin/main", 0, nil)
	if err != nil {
		log.Print("fail to read testBin\n")
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestDecode(t *testing.T) {

	insts, err := decode(code, 0x481840)
	if err != nil {
		t.Error(err)
	}

	for _, inst := range insts {
		fmt.Printf("%x: %s\n", inst.Loc.PC, inst.Text(proc.GoFlavour, bi))
	}
}

func TestGetEpilogue(t *testing.T) {

	insts, err := decode(code, 0x481840)
	if err != nil {
		t.Error(err)
	}

	epiInsts := GetEpilogue(insts)

	for _, inst := range epiInsts {
		fmt.Printf("%x: %s\n", inst.Loc.PC, inst.Text(proc.GoFlavour, bi))
	}

}

// TODO find a better way to test this function
// Now we test it in fn_manager module
func TestGetOriginalRegBackup(t *testing.T) {

	insts, err := decode(code, 0x481840)
	if err != nil {
		t.Error(err)
	}

	epiInsts := GetEpilogue(insts)
	regBack, regRestore := GetOriginalRegBackup(epiInsts)

	fmt.Println("Reg Back:")
	for _, v := range regBack {
		fmt.Printf("%x", v)

	}
	fmt.Println()
	fmt.Println("Reg Restore:")
	for _, v := range regRestore {
		fmt.Printf("%x", v)
	}

}
