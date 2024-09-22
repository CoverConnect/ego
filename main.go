package main

import (
	"math/rand"
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
	instrument.Trace("main.target")
	Tracee()

	select {}
}

func Tracee() {
	go func() {
		for {
			a := "omg: " + strconv.Itoa(rand.Intn(10))
			b := make(map[int]int, 0)
			b[3] = 3
			c := []int{123, 33, 43, 41, 343}
			p := Point{a: a, b: b, c: c}
			target(p)

			time.Sleep(1 * time.Second)
		}
	}()
}

//go:noinline
func target(p Point) {
	//fmt.Printf("%v\n", p)
}
