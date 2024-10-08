package tracee

import (
	"math/rand"
)

type Point struct {
	a string
	b map[int]int
	c []int
}

//go:noinline
func Entry() { /// ---> hook  fork 1 g process register

	a := rand.Intn(10)
	//go f1(a)
	//go f2(a)

	go recur(a)

	//F2()
	//F3()

}

//go:noinline
func f1(a int) int {

	if a%2 == 0 {
		return a //// ---> hook
	}
	return a + 2 ///   ---> hook
}

//go:noinline
func f2(a int) int {
	if a%2 == 0 {
		return a
	}

	for idx := 0; idx < 5; idx++ {
		f21(a)
	}

	return 10
	//f22()
	//f23()
}

//go:noinline
func f21(a int) int {
	b := rand.Intn(10)
	c := a * b
	if c%3 == 0 {
		return f22(c)
	}

	return f23(c)
}

//go:noinline
func f22(a int) int {

	return a * 100
}

//go:noinline
func f23(a int) int {
	return a - 19
}

//go:noinline
func recur(a int) int {
	if a == 0 {
		return 0
	}

	return recur(a - 1)
}

func max(a, b int) int {
	if a > b {
		return a
	} else {
		return b
	}
}
