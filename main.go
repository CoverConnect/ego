package main

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/CoverConnect/ego/pkg/instrument"
)

var prefix = "main.target"

type Point struct {
	a string
	b map[int]int
	c []int
}

func main() {
	// tracee body
	go func() {
		for {
			a := "omg: " + strconv.Itoa(rand.Intn(10))
			b := make(map[int]int, 0)
			b[3] = 3
			c := []int{123, 33, 43, 41, 343}
			p := Point{a: a, b: b, c: c}
			target(p)
		}
	}()

	// start instrument

	exec, err := os.Executable()
	if err != nil {
		log.Printf("Fail to load exec file. path:%s", exec)
		return
	}

	in := instrument.NewInstrument(exec)
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
	//fmt.Printf("%v\n", p)
}
