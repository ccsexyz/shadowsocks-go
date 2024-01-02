package utils

import (
	"container/list"
	"sync"
)

// LRU implements a simple and thread-safe LRU cache
type LRU struct {
	lock     *sync.RWMutex
	elements map[interface{}]*list.Element
	entries  *list.List
	async    AsyncRunner
	maxlen   int

	onDelete DeleteCallback
	onCheck  CheckCallback
}

type entry struct {
	key   interface{}
	value interface{}
}

// CheckCallback is used to check if a key can be deleted
// the key won't be deleted if it returns true
type CheckCallback func(key, value interface{}) (ok bool)

// DeleteCallback is called when a key is deleting
type DeleteCallback func(key, value interface{})

// NewLRU init a new lru
func NewLRU(maxlen int, onCheck CheckCallback, onDelete DeleteCallback) *LRU {
	lru := &LRU{
		lock:     &sync.RWMutex{},
		elements: make(map[interface{}]*list.Element),
		entries:  list.New(),
		maxlen:   0,
		onDelete: onDelete,
		onCheck:  onCheck,
	}
	if maxlen > 0 {
		lru.maxlen = maxlen
	}
	return lru
}

// Add inserts new key and value into the lru
func (lru *LRU) Add(key, value interface{}) {
	lru.lock.Lock()
	defer lru.lock.Unlock()

	ele, ok := lru.elements[key]
	if ok {
		lru.entries.MoveToFront(ele)
		ele.Value.(*entry).value = value
		return
	}

	ent := &entry{key: key, value: value}
	ele = lru.entries.PushFront(ent)
	lru.elements[key] = ele

	if lru.entries.Len() > lru.maxlen {
		lru.tryDeleteOldest()
	}

	return
}

// Load get the value from lru cache with given key, ok returns false if
// key is not in the lru
func (lru *LRU) Load(key interface{}) (value interface{}, ok bool) {
	lru.lock.RLock()
	defer lru.lock.RUnlock()

	ele, ok := lru.elements[key]
	if ok {
		value = ele.Value.(*entry).value
		lru.async.Run(func() {
			lru.lock.Lock()
			defer lru.lock.Unlock()
			lru.entries.MoveToFront(ele)
		})
	}

	return
}

// Has test if the key is in the lru cache, and don't update the lru
func (lru *LRU) Has(key interface{}) (ok bool) {
	lru.lock.RLock()
	defer lru.lock.RUnlock()

	_, ok = lru.elements[key]

	return
}

// Delete deletes the key from cache, returns its value and if cache has the key
func (lru *LRU) Delete(key interface{}) (value interface{}, ok bool) {
	lru.lock.Lock()
	defer lru.lock.Unlock()

	ele, ok := lru.elements[key]
	if ok {
		value = ele.Value.(*entry).value
		lru.deleteElement(ele)
	}

	return
}

// DeleteOldest deletes the oldest entry from cache
// returns its key, value and if delete is successful
func (lru *LRU) DeleteOldest() (key, value interface{}, ok bool) {
	lru.lock.Lock()
	defer lru.lock.Unlock()

	ele := lru.entries.Back()
	if ele == nil {
		return
	}

	ent := ele.Value.(*entry)
	key = ent.key
	value = ent.value

	lru.deleteElement(ele)

	return
}

// Length returns the number of entries
func (lru *LRU) Length() int {
	lru.lock.RLock()
	defer lru.lock.RUnlock()
	return lru.entries.Len()
}

func (lru *LRU) tryDeleteOldest() {
	ele := lru.entries.Back()
	if ele == nil {
		return
	}
	if lru.onCheck != nil {
		ent := ele.Value.(*entry)
		ok := lru.onCheck(ent.key, ent.value)
		if ok {
			lru.entries.MoveToFront(ele)
			return
		}
	}
	lru.deleteElement(ele)
}

func (lru *LRU) deleteElement(ele *list.Element) {
	if ele == nil {
		return
	}
	lru.entries.Remove(ele)
	ent := ele.Value.(*entry)
	delete(lru.elements, ent.key)
	if lru.onDelete != nil {
		lru.async.Run(func() {
			lru.onDelete(ent.key, ent.value)
		})
	}
}
