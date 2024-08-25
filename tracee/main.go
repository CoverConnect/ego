package main

import (
	"fmt"
	"math/rand"
	"time"
)

type receiver struct {
	f1 int
	f2 int
}

//go:noinline
func (r receiver) target1(a, b int, c string) int {
	fmt.Printf("value %d,%d %s| f1, f2: %d, %d \n", a, b, c, r.f1, r.f2)
	target2()
	target3()
	return a + b

}

//go:noinline
func target2() {
	target4()
}

//go:noinline
func target3() {
}

//go:noinline
func target4() {
}

func main() {

	r := receiver{f1: 0x11, f2: 0x22}

	for {
		time.Sleep(1 * time.Second)
		a := rand.Intn(10)
		b := rand.Intn(10)
		str := string("hello")
		r.target1(a, b, str)
	}

}
