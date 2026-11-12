package service

// freeChain is an indexed FIFO. Reservation and allocation are constant time;
// contiguous integer links avoid retaining one heap object per free identifier.
type freeChain struct {
	previous, next []int32
	available      []bool
	head, tail     int32
	count          int
}

func newFreeChain(size int) freeChain {
	chain := freeChain{previous: make([]int32, size), next: make([]int32, size), available: make([]bool, size), head: -1, tail: -1, count: size}
	if size > 0 {
		chain.head = 0
		chain.tail = int32(size - 1)
	}
	for i := range size {
		chain.previous[i] = int32(i) - 1
		chain.next[i] = int32(i) + 1
		chain.available[i] = true
	}
	if size > 0 {
		chain.next[size-1] = -1
	}
	return chain
}
func (chain *freeChain) len() int   { return chain.count }
func (chain *freeChain) first() int { return int(chain.head) }
func (chain *freeChain) contains(index int) bool {
	return index >= 0 && index < len(chain.available) && chain.available[index]
}
func (chain *freeChain) remove(index int) {
	if !chain.contains(index) {
		return
	}
	previous, next := chain.previous[index], chain.next[index]
	if previous < 0 {
		chain.head = next
	} else {
		chain.next[previous] = next
	}
	if next < 0 {
		chain.tail = previous
	} else {
		chain.previous[next] = previous
	}
	chain.available[index] = false
	chain.count--
}
func (chain *freeChain) addBack(index int) {
	if index < 0 || index >= len(chain.available) || chain.available[index] {
		return
	}
	chain.previous[index] = chain.tail
	chain.next[index] = -1
	if chain.tail < 0 {
		chain.head = int32(index)
	} else {
		chain.next[chain.tail] = int32(index)
	}
	chain.tail = int32(index)
	chain.available[index] = true
	chain.count++
}
func (chain *freeChain) moveToFront(index int) {
	if !chain.contains(index) || chain.head == int32(index) {
		return
	}
	chain.remove(index)
	chain.previous[index] = -1
	chain.next[index] = chain.head
	if chain.head < 0 {
		chain.tail = int32(index)
	} else {
		chain.previous[chain.head] = int32(index)
	}
	chain.head = int32(index)
	chain.available[index] = true
	chain.count++
}
