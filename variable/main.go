package main

import (
	"runtime"

	"github.com/go-delve/delve/pkg/proc"
)

func main() {

	bi := proc.NewBinaryInfo(runtime.GOOS, runtime.GOARCH)

}
