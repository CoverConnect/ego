package main

import (
	"fmt"
	"math/rand"
	"time"
)

type Point struct {
	a int
	b int
}

func main() {
	for {
		time.Sleep(1 * time.Second)
		p := Point{a: rand.Intn(10), b: rand.Intn(10)}
		target(p)
	}
}

//go:noinline
func target(p Point) {
	fmt.Printf("%v\n", p)
}
