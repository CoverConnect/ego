package main

import (
	"time"

	"github.com/CoverConnect/ego/pkg/instrument"
	"github.com/CoverConnect/ego/tracee"
)

var prefix = "github.com/CoverConnect/ego/tracee"

func main() {
	// tracee body
	instrument.Trace(prefix)
	startTracee()

}

func startTracee() {
	for {
		time.Sleep(2 * time.Second)
		tracee.Entry()

	}
}
