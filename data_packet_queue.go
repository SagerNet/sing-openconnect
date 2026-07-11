package openconnect

import "sync"

const dataPacketQueueCapacity = 512

type dataPacketQueue[T any] struct {
	access sync.Mutex
	items  []T
	head   int
	length int
	wake   chan struct{}
}

func newDataPacketQueueWithCapacity[T any](capacity int) *dataPacketQueue[T] {
	if capacity < 1 {
		capacity = 1
	}
	return &dataPacketQueue[T]{
		items: make([]T, capacity),
		wake:  make(chan struct{}, 1),
	}
}

func (q *dataPacketQueue[T]) PushBatch(items []T, release func(T)) uint64 {
	if len(items) == 0 {
		return 0
	}
	q.access.Lock()
	wasEmpty := q.length == 0
	var dropped uint64
	for _, item := range items {
		if q.length == len(q.items) {
			droppedItem := q.items[q.head]
			var zero T
			q.items[q.head] = zero
			q.head = (q.head + 1) % len(q.items)
			q.length--
			dropped++
			if release != nil {
				release(droppedItem)
			}
		}
		tail := (q.head + q.length) % len(q.items)
		q.items[tail] = item
		q.length++
	}
	q.access.Unlock()
	if wasEmpty {
		q.signal()
	}
	return dropped
}

func (q *dataPacketQueue[T]) Pop(maximumItems int) []T {
	q.access.Lock()
	count := q.length
	if maximumItems > 0 {
		count = min(count, maximumItems)
	}
	if count == 0 {
		q.access.Unlock()
		return nil
	}
	items := make([]T, count)
	for index := range count {
		itemIndex := (q.head + index) % len(q.items)
		items[index] = q.items[itemIndex]
		var zero T
		q.items[itemIndex] = zero
	}
	q.head = (q.head + count) % len(q.items)
	q.length -= count
	hasMore := q.length > 0
	q.access.Unlock()
	if hasMore {
		q.signal()
	}
	return items
}

func (q *dataPacketQueue[T]) Wake() <-chan struct{} {
	return q.wake
}

func (q *dataPacketQueue[T]) Drain(release func(T)) {
	for _, item := range q.Pop(0) {
		if release != nil {
			release(item)
		}
	}
}

func (q *dataPacketQueue[T]) signal() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}
