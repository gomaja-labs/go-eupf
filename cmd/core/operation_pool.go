package core

// Operation is one planned change in a quiesced map transaction. All slots
// are reserved before any PDR detaches; every detach precedes new map values.
// Exact rollback belongs to the journal, including counters and policer state.
type Operation struct {
	Reserve func() error
	Detach  func() error
	Apply   func() error
}
type OperationPool struct {
	Before     func() error
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
	for _, op := range pool.operations {
		if op.Detach != nil {
			if err := op.Detach(); err != nil {
				return err
			}
		}
	}
	for _, op := range pool.operations {
		if op.Apply != nil {
			if err := op.Apply(); err != nil {
				return err
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
	operation.Reserve, operation.Detach, operation.Apply = wrap(operation.Reserve), wrap(operation.Detach), wrap(operation.Apply)
	pool.Add(operation)
}
