// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"sync"
	"time"

	"github.com/google/syzkaller/prog"
)

// ============================================================================
// Solo Execution Pair Cache
// ============================================================================
// This module caches the solo execution results (VarName pair sets) for programs.
// When the same program participates in multiple barrier combinations,
// its solo execution result can be reused, avoiding redundant executions.
// This can reduce execution overhead by up to ~66% in ideal cases.
// ============================================================================

// SoloPairCache caches solo execution results for programs.
type SoloPairCache struct {
	mu    sync.RWMutex
	cache map[string]*CachedSoloPairs
	order []string // LRU order tracking
	max   int      // Maximum cache size

	// Statistics
	hits   int
	misses int
}

// CachedSoloPairs stores cached solo execution results.
type CachedSoloPairs struct {
	Pairs     *VarNamePairSet
	Timestamp int64 // Unix timestamp when cached
}

// NewSoloPairCache creates a new solo pair cache with the specified max size.
func NewSoloPairCache(maxSize int) *SoloPairCache {
	if maxSize <= 0 {
		maxSize = 10000 // Default size
	}
	return &SoloPairCache{
		cache: make(map[string]*CachedSoloPairs),
		order: make([]string, 0, maxSize),
		max:   maxSize,
	}
}

// Get retrieves cached solo pairs for a program.
// Returns (pairs, true) if found, (nil, false) if not cached.
func (c *SoloPairCache) Get(p *prog.Prog) (*VarNamePairSet, bool) {
	if c == nil || p == nil {
		return nil, false
	}

	sig := progSignature(p)

	c.mu.RLock()
	cached, ok := c.cache[sig]
	c.mu.RUnlock()

	if ok && cached != nil {
		c.mu.Lock()
		c.hits++
		// Move to end of order (LRU update)
		c.moveToEnd(sig)
		c.mu.Unlock()
		return cached.Pairs, true
	}

	c.mu.Lock()
	c.misses++
	c.mu.Unlock()
	return nil, false
}

// Put stores solo pairs for a program in the cache.
func (c *SoloPairCache) Put(p *prog.Prog, pairs *VarNamePairSet) {
	if c == nil || p == nil || pairs == nil {
		return
	}

	sig := progSignature(p)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if already cached
	if _, exists := c.cache[sig]; exists {
		// Update existing entry and move to end
		c.cache[sig] = &CachedSoloPairs{
			Pairs:     pairs,
			Timestamp: currentTimestamp(),
		}
		c.moveToEnd(sig)
		return
	}

	// Check if we need to evict
	for len(c.cache) >= c.max && len(c.order) > 0 {
		// Evict oldest entry (LRU)
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.cache, oldest)
	}

	// Add new entry
	c.cache[sig] = &CachedSoloPairs{
		Pairs:     pairs,
		Timestamp: currentTimestamp(),
	}
	c.order = append(c.order, sig)
}

// Invalidate removes a program from the cache.
// This should be called when a program is mutated.
func (c *SoloPairCache) Invalidate(p *prog.Prog) {
	if c == nil || p == nil {
		return
	}

	sig := progSignature(p)

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.cache[sig]; exists {
		delete(c.cache, sig)
		c.removeFromOrder(sig)
	}
}

// Clear empties the entire cache.
func (c *SoloPairCache) Clear() {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = make(map[string]*CachedSoloPairs)
	c.order = make([]string, 0, c.max)
}

// GetStats returns cache statistics.
func (c *SoloPairCache) GetStats() (size, hits, misses int, hitRate float64) {
	if c == nil {
		return 0, 0, 0, 0
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	size = len(c.cache)
	hits = c.hits
	misses = c.misses
	total := hits + misses
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}
	return
}

// moveToEnd moves a key to the end of the LRU order.
func (c *SoloPairCache) moveToEnd(sig string) {
	for i, s := range c.order {
		if s == sig {
			// Remove from current position
			c.order = append(c.order[:i], c.order[i+1:]...)
			// Add to end
			c.order = append(c.order, sig)
			return
		}
	}
	// Not found in order, add it
	c.order = append(c.order, sig)
}

// removeFromOrder removes a key from the LRU order.
func (c *SoloPairCache) removeFromOrder(sig string) {
	for i, s := range c.order {
		if s == sig {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}

// currentTimestamp returns the current Unix timestamp for LRU ordering.
func currentTimestamp() int64 {
	return time.Now().Unix()
}


