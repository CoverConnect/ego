package main

import (
	"fmt"
	"math/rand"
	"time"
)

func main() {

	for {
		time.Sleep(1 * time.Second)
		a := rand.Intn(10)
		b := rand.Intn(10)

		target(a, b)
	}

}

//go:noinline
func target(a, b int) int {
	c := rand.Intn(10)
	fmt.Println("value %d,%d", a, b)
	return a + b + c

}
