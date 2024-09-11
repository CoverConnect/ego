package main

import (
	"fmt"
	"log"
	"time"

	"github.com/CoverConnect/ego/pkg/instrument"
)

var binaryPath = "/root/ego/tracee/tracee"

var prefix = "main.Target"

func main() {

	in := instrument.NewInstrument(binaryPath)

	in.ProbeFunctionWithPrefix(prefix)
	in.Start()

	log.Printf("=== start ===\n")
	for {
		fmt.Printf(".")
		time.Sleep(1 * time.Second)
	}

}
