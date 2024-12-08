package internal

type FunctionManager struct {
	functions map[string]*Function
}

type Function struct {
	Name string
}

func NewFunctionManager() *FunctionManager {
	return &FunctionManager{
		functions: make(map[string]*Function),
	}
}

func (fm FunctionManager) GetAll() []*Function {
	var functions = make([]*Function, 0)
	for _, f := range fm.functions {
		functions = append(functions, f)
	}
	return functions
}

  	fm.functions[functionName] = &Function{Name: functionName}
}

func (fm *FunctionManager) UnregisterByName(name string) {
	if _, ok := fm.functions[name]; !ok {
		return
	}
	delete(fm.functions, name)
}
