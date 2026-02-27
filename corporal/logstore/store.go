package logstore

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

// Store is a thread-safe in-memory ring buffer of log entries.
type Store struct {
	mu          sync.RWMutex
	entries     []Entry
	maxSize     int
	nextID      atomic.Uint64
	levelFilter map[string]bool
}

// defaultLevelFilter returns the default level filter: debug (and trace) excluded as too noisy.
func defaultLevelFilter() map[string]bool {
	return map[string]bool{
		"trace":   false,
		"debug":   false,
		"info":    true,
		"warning": true,
		"error":   true,
		"fatal":   true,
		"panic":   true,
	}
}

// NewStore creates a new log store with the given maximum number of entries.
// When full, the oldest entry is dropped when a new one is added.
// By default, debug (and trace) are excluded from storage to reduce noise.
func NewStore(maxSize int) *Store {
	if maxSize <= 0 {
		maxSize = 1000
	}
	return &Store{
		entries:     make([]Entry, 0, maxSize),
		maxSize:     maxSize,
		levelFilter: defaultLevelFilter(),
	}
}

// Add appends a log entry. If at capacity, the oldest entry is removed.
func (s *Store) Add(e Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e.ID = fmt.Sprintf("%d", s.nextID.Add(1))
	if len(s.entries) >= s.maxSize {
		s.entries = s.entries[1:]
	}
	s.entries = append(s.entries, e)
}

// List returns a page of entries (newest first) and the total count.
// limit and offset are applied to the newest-first view; offset 0 is the most recent entry.
func (s *Store) List(limit, offset int) ([]Entry, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := len(s.entries)
	if total == 0 {
		return nil, 0
	}
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	// Newest is at index total-1; we return [total-1-offset-limit+1 .. total-1-offset] in reverse order.
	start := total - offset - limit
	if start < 0 {
		start = 0
	}
	end := total - offset
	if end <= start {
		return nil, total
	}
	page := make([]Entry, 0, end-start)
	for i := end - 1; i >= start; i-- {
		page = append(page, s.entries[i])
	}
	return page, total
}

// Delete removes the entry with the given id. Returns true if an entry was removed.
func (s *Store) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, e := range s.entries {
		if e.ID == id {
			s.entries = append(s.entries[:i], s.entries[i+1:]...)
			return true
		}
	}
	return false
}

// DeleteAll removes all entries.
func (s *Store) DeleteAll() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries = s.entries[:0]
}

// SetLevelsEnabled replaces the current level filter with the provided one.
// The map keys are case-insensitive log level names (e.g. \"debug\", \"info\", \"warning\", \"error\").
// When a filter is set, only levels explicitly enabled (true) are stored.
// Passing nil resets to the default filter (debug and trace excluded).
func (s *Store) SetLevelsEnabled(levels map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if levels == nil {
		s.levelFilter = defaultLevelFilter()
		return
	}

	filter := make(map[string]bool, len(levels))
	for level, enabled := range levels {
		filter[strings.ToLower(level)] = enabled
	}
	s.levelFilter = filter
}

// LevelsEnabled returns a copy of the current level filter.
func (s *Store) LevelsEnabled() map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.levelFilter == nil {
		return defaultLevelFilter()
	}

	out := make(map[string]bool, len(s.levelFilter))
	for level, enabled := range s.levelFilter {
		out[level] = enabled
	}

	return out
}

// shouldStoreLevel decides whether a log with the given level should be stored.
func (s *Store) shouldStoreLevel(level string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.levelFilter == nil {
		return true // fallback if filter was never set
	}

	enabled, ok := s.levelFilter[strings.ToLower(level)]
	if !ok {
		return false
	}
	return enabled
}

