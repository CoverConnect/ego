package tracee

type Point struct {
	a string
	b map[int]int
	c []int
}

//go:noinline
func F1() {
	F2()
	F3()
}

//go:noinline
func F2() {
	F4()
}

//go:noinline
func F3() {}

//go:noinline
func F4() {}
