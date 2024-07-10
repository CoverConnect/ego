package main

import "time"

func main() {

	for {
		time.Sleep(1 * time.Second)
		target(4, 5)
	}

}

//go:noinline
func target(a, b int) int {

	return a + b

}
