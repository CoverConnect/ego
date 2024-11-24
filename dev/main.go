package main

import (
	"fmt"
	"time"

	_ "github.com/CoverConnect/ego/cmd/ego"
)

func main() {
	// tracee body

	go func() {
		for {
			go simpleFlow()
			time.Sleep(1 * time.Second)
			go recur(10)
		}
	}()

	for {
		fmt.Print(".")
		time.Sleep(10 * time.Second)

	}
}

type Point struct {
	Str      string
	IntMap   map[string]int
	IntSlice []int
}

func NewPoint() *Point {
	p := &Point{Str: "hello", IntMap: make(map[string]int), IntSlice: make([]int, 10)}
	p.IntMap["key1"] = 1
	for idx, v := range p.IntSlice {
		v += idx
	}
	return p
}

//go:noinline
func simpleFlow() {
	p := NewPoint()
	p1 := s1(*p)
	p1.IntSlice[2] = 4
}

//go:noinline
func s1(p Point) Point {

	p.IntMap["s1key2"] = 2
	p11 := s11(p)
	p12 := s12(p11)
	p12.IntMap["keys1end"] = 7
	return p12
}

//go:noinline
func s11(p Point) Point {
	p.Str = "s11 change"
	return p
}

//go:noinline
func s12(p Point) Point {
	p.IntSlice = append(p.IntSlice, 12)
	return p
}

//go:noinline
func s111(p Point) {

}

//go:noinline
func recur(a int) int {
	if a == 0 {
		return 0
	}
	time.Sleep(1 * time.Second)
	return recur(a-1) - 1
}
