// Package utils provides shared utility types used across R3TRIVE.
package utils

import "sync"

// RingBuffer is a thread-safe, fixed-capacity circular buffer.
// When full, new items overwrite the oldest entries.
type RingBuffer[T any] struct {
	mu    sync.RWMutex
	items []T
	head  int // next write position
	size  int // current number of items
	cap   int // maximum capacity
}

// NewRingBuffer creates a new ring buffer with the given capacity.
func NewRingBuffer[T any](capacity int) *RingBuffer[T] {
	if capacity < 1 {
		capacity = 1
	}
	return &RingBuffer[T]{
		items: make([]T, capacity),
		cap:   capacity,
	}
}

// Push adds an item to the buffer. If the buffer is full, the oldest
// item is overwritten.
func (rb *RingBuffer[T]) Push(item T) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.items[rb.head] = item
	rb.head = (rb.head + 1) % rb.cap

	if rb.size < rb.cap {
		rb.size++
	}
}

// Len returns the current number of items in the buffer.
func (rb *RingBuffer[T]) Len() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.size
}

// Cap returns the maximum capacity of the buffer.
func (rb *RingBuffer[T]) Cap() int {
	return rb.cap
}

// Snapshot returns a copy of all items in the buffer, ordered from
// oldest to newest.
func (rb *RingBuffer[T]) Snapshot() []T {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	result := make([]T, rb.size)
	if rb.size == 0 {
		return result
	}

	if rb.size < rb.cap {
		// Buffer not full yet — items start at 0
		copy(result, rb.items[:rb.size])
	} else {
		// Buffer full — oldest item is at head (it was just overwritten next)
		n := copy(result, rb.items[rb.head:])
		copy(result[n:], rb.items[:rb.head])
	}

	return result
}

// Last returns the N most recent items, ordered oldest to newest.
func (rb *RingBuffer[T]) Last(n int) []T {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	if n > rb.size {
		n = rb.size
	}
	if n == 0 {
		return nil
	}

	result := make([]T, n)

	// Start position: n items back from head
	start := (rb.head - n + rb.cap) % rb.cap
	if start+n <= rb.cap {
		copy(result, rb.items[start:start+n])
	} else {
		firstPart := rb.cap - start
		copy(result, rb.items[start:])
		copy(result[firstPart:], rb.items[:n-firstPart])
	}

	return result
}
