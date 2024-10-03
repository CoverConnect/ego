package main

import (
	"fmt"
	"time"

	"github.com/CoverConnect/ego/pkg/instrument"
	"github.com/CoverConnect/ego/tracee"
)

var prefix = "github.com/CoverConnect/ego/tracee"

func main() {
	// tracee body
	instrument.Trace(prefix)
	Tracee()

	select {}
}

func Tracee() {
	for {

		tracee.F1()
		time.Sleep(1 * time.Second)
		fmt.Printf(".")
	}
}
