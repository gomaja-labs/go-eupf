package core

// Operation is one planned map change. Exact rollback belongs to the map
// transaction, including the original slot, counters and QoS runtime state.
type Operation struct {
	Reserve func() error
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
	for _, operation := range pool.operations {
		if err := operation.Apply(); err != nil {
			return err
		}
	}
	return nil
}

func (pool *OperationPool) AddRule(kind uint8, id uint32, operation Operation) {
	reserve := operation.Reserve
	if reserve != nil {
		operation.Reserve = func() error {
			if err := reserve(); err != nil {
				return &ruleFailure{kind, id, err}
			}
			return nil
		}
	}
	apply := operation.Apply
	operation.Apply = func() error {
		if err := apply(); err != nil {
			return &ruleFailure{kind, id, err}
		}
		return nil
	}
	pool.Add(operation)
}
