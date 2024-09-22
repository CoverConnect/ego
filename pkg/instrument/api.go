package instrument

func Trace(sig string) {
	in.ProbeFunctionWithPrefix(sig)
}

func UnTrace(sig string) {
	// TODO in.UnProbeFunctionWithPrefix(sig)
}
