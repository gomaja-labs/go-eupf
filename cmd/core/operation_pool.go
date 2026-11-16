package core

// Operation is one planned change in a journalled map transaction. All slots
// are reserved before publication; dependencies and new PDRs precede detachment.
// Exact rollback belongs to the journal, including counters and policer state.
type Operation struct {
	Reserve  func() error
	Detach   func() error
	Apply    func() error
	Retire   func() error
	rule     bool
	ruleKind uint8
	ruleID   uint32
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
				return op.failure(err)
			}
		}
	}
	// TS 29.244 V20.1.0 clauses 6.3.2.3 and 6.3.3.3: the final
	// outcome is atomic. Make before break keeps unrelated traffic flowing.
	for phase := 0; phase < 3; phase++ {
		if phase == 2 && pool.Publish != nil {
			if err := pool.Publish(); err != nil {
				return err
			}
		}
		for _, op := range pool.operations {
			var action func() error
			switch phase {
			case 0:
				action = op.Apply
			case 1:
				action = op.Detach
			case 2:
				action = op.Retire
			}
			if action != nil {
				if err := action(); err != nil {
					return op.failure(err)
				}
			}
		}
	}

	return nil
}
func (pool *OperationPool) AddRule(kind uint8, id uint32, operation Operation) {
	operation.rule, operation.ruleKind, operation.ruleID = true, kind, id
	pool.Add(operation)
}
func (operation Operation) failure(err error) error {
	if operation.rule {
		return &ruleFailure{operation.ruleKind, operation.ruleID, err}
	}
	return err
}
