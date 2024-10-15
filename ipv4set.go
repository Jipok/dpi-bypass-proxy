package main

import (
	"net"
	"sync"
)

type IPv4Set struct {
	mu       sync.RWMutex
	set      map[string]struct{}
	order    []string
	capacity int
}

func NewIPv4Set(capacity int) *IPv4Set {
	return &IPv4Set{
		set:      make(map[string]struct{}),
		order:    make([]string, 0, capacity),
		capacity: capacity,
	}
}

// Add inserts an IPv4 address. Returns true if added, false if duplicate.
func (s *IPv4Set) Add(ip net.IP) bool {
	ipStr := ip.To4().String()
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.set[ipStr]; exists {
		return false
	}

	if len(s.order) >= s.capacity {
		// Remove oldest
		old := s.order[0]
		s.order = s.order[1:]
		delete(s.set, old)
	}

	s.set[ipStr] = struct{}{}
	s.order = append(s.order, ipStr)
	return true
}

// Exists checks if an IPv4 address is in the set.
func (s *IPv4Set) Exists(ip net.IP) bool {
	ipStr := ip.To4().String()
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.set[ipStr]
	return exists
}
