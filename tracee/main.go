package main

import (
	"fmt"
	"math/rand"
	"time"
)

func main() {

	for {
		time.Sleep(1 * time.Second)
		target(4, 5)
	}

}

//go:noinline
func target(a, b int) int {
	c := rand.Intn(10)
	fmt.Println("value %d,%d", a+c, b)
	return a + b + c

}
