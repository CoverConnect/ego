package main

import (
	"fmt"
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
			c1, c2, err := target(p)
			fmt.Printf("%d,%d,%v\n", c1, c2, err)

			time.Sleep(1 * time.Second)
		}
	}()
}

//go:noinline
func target(p Point) (c1, c2 int, err error) {

	v := rand.Intn(10)

	p.c = append(p.c, v)

	return p.c[0], p.c[1], fmt.Errorf("no error")
}
