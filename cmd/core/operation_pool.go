package core

// Operation is one planned change in a journalled map transaction. All slots
// are reserved before publication; dependencies and new PDRs precede detachment.
// Exact rollback belongs to the journal, including counters and policer state.
type Operation struct {
	Reserve func() error
	Detach  func() error
	Apply   func() error
	Retire  func() error
}
type OperationPool struct {
	Before     func() error
	Publish    func() error
	operations []Operation
}

func NewOperationPool() *OperationPool { return &OperationPool{} }
func (pool *OperationPool) Add(operation Operation) {
	pool.operations = append(pool.operations, operation)
}
func (pool *OperationPool) Commit() error {
	if pool.Before != nil {
		if err := pool.Before(); err != nil {
			return err
		}
	}
	for _, op := range pool.operations {
		if op.Reserve != nil {
			if err := op.Reserve(); err != nil {
				return err
			}
		}
	}
	// TS 29.244 V20.1.0 clauses 6.3.2.3 and 6.3.3.3: the final
	// outcome is atomic. Make before break keeps unrelated traffic flowing.
	for index, step := range []func(Operation) func() error{
		func(op Operation) func() error { return op.Apply },
		func(op Operation) func() error { return op.Detach },
		func(op Operation) func() error { return op.Retire },
	} {
		if index == 2 && pool.Publish != nil {
			if err := pool.Publish(); err != nil {
				return err
			}
		}
		for _, op := range pool.operations {
			if action := step(op); action != nil {
				if err := action(); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func (pool *OperationPool) AddRule(kind uint8, id uint32, operation Operation) {
	wrap := func(step func() error) func() error {
		if step == nil {
			return nil
		}
		return func() error {
			if err := step(); err != nil {
				return &ruleFailure{kind, id, err}
			}
			return nil
		}
	}
	operation.Reserve, operation.Detach, operation.Apply, operation.Retire = wrap(operation.Reserve), wrap(operation.Detach), wrap(operation.Apply), wrap(operation.Retire)
	pool.Add(operation)
}
