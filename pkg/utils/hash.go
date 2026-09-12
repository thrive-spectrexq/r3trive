package utils

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"
	"sync"
)

// HashString computes a 64-bit FNV-1a hash of a string.
func HashString(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

// AlertFingerprint generates a unique deterministic fingerprint for alert deduplication.
func AlertFingerprint(hostID, ruleID, primaryEntity string) string {
	raw := fmt.Sprintf("%s:%s:%s", hostID, ruleID, primaryEntity)
	h := HashString(raw)
	return fmt.Sprintf("fp-%016x", h)
}

// ConsistentHashRing implements consistent hashing with virtual nodes for distributed event routing.
type ConsistentHashRing struct {
	vnodes  int
	ring    []uint64
	nodeMap map[uint64]string
	nodes   map[string]bool
	mu      sync.RWMutex
}

// NewConsistentHashRing creates a ring with virtual node replication factor.
func NewConsistentHashRing(vnodes int) *ConsistentHashRing {
	if vnodes <= 0 {
		vnodes = 50
	}
	return &ConsistentHashRing{
		vnodes:  vnodes,
		ring:    make([]uint64, 0),
		nodeMap: make(map[uint64]string),
		nodes:   make(map[string]bool),
	}
}

// AddNode adds a physical node to the ring.
func (c *ConsistentHashRing) AddNode(node string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.nodes[node] {
		return
	}
	c.nodes[node] = true

	for i := 0; i < c.vnodes; i++ {
		vkey := node + "#" + strconv.Itoa(i)
		h := HashString(vkey)
		c.ring = append(c.ring, h)
		c.nodeMap[h] = node
	}
	sort.Slice(c.ring, func(i, j int) bool { return c.ring[i] < c.ring[j] })
}

// RemoveNode removes a physical node from the ring.
func (c *ConsistentHashRing) RemoveNode(node string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.nodes[node] {
		return
	}
	delete(c.nodes, node)

	newRing := make([]uint64, 0, len(c.ring))
	for _, h := range c.ring {
		if c.nodeMap[h] == node {
			delete(c.nodeMap, h)
		} else {
			newRing = append(newRing, h)
		}
	}
	c.ring = newRing
}

// GetNode locates the responsible node for a given key.
func (c *ConsistentHashRing) GetNode(key string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.ring) == 0 {
		return ""
	}

	h := HashString(key)
	idx := sort.Search(len(c.ring), func(i int) bool {
		return c.ring[i] >= h
	})

	if idx == len(c.ring) {
		idx = 0
	}

	return c.nodeMap[c.ring[idx]]
}
