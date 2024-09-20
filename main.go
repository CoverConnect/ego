package main

import (
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/CoverConnect/ego/pkg/instrument"
)

var binaryPath = "/root/ego/tracee/tracee"

var prefix = "main.Target"

type Point struct {
	a int
	b int
}

func main() {

	go func() {
		for {
			time.Sleep(1 * time.Second)
			p := Point{a: rand.Intn(10), b: rand.Intn(10)}
			target(p)
		}
	}()

	in := instrument.NewInstrument(binaryPath)

	in.ProbeFunctionWithPrefix(prefix)
	in.Start()

	log.Printf("=== start ===\n")
	for {
		fmt.Printf(".")
		time.Sleep(1 * time.Second)
	}

}

//go:noinline
func target(p Point) {
	fmt.Printf("%v\n", p)
}
