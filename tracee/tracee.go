package tracee

import "math/rand"

type Point struct {
	a string
	b map[int]int
	c []int
}

//go:noinline
func Entry() { /// ---> hook  fork 1 g process register

	a := rand.Intn(10)
	f1(a)
	f2

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
func f2() {
	//f21()
	//f22()
	//f23()
}

//go:noinline
func f21() {}

//go:noinline
func f22() {}

//go:noinline
func f23() {}

//go:noinline
func f3() {}
