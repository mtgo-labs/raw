package mtproto

import (
	"errors"
	"net"
	"sort"
	"strconv"
	"sync"
)

var ErrInvalidEndpoint = errors.New("mtproto: invalid DC endpoint")

type DCEndpoint struct {
	ID      int
	Address string
	IPv6    bool
}

type EndpointTable struct {
	mu        sync.RWMutex
	endpoints map[int]DCEndpoint
}

func NewEndpointTable() *EndpointTable {
	return &EndpointTable{endpoints: make(map[int]DCEndpoint)}
}

func (table *EndpointTable) Set(endpoint DCEndpoint) error {
	if table == nil || !validEndpoint(endpoint) {
		return ErrInvalidEndpoint
	}
	table.mu.Lock()
	if table.endpoints == nil {
		table.endpoints = make(map[int]DCEndpoint)
	}
	table.endpoints[endpoint.ID] = endpoint
	table.mu.Unlock()
	return nil
}

func (table *EndpointTable) Get(id int) (DCEndpoint, bool) {
	if table == nil {
		return DCEndpoint{}, false
	}
	table.mu.RLock()
	endpoint, ok := table.endpoints[id]
	table.mu.RUnlock()
	return endpoint, ok
}

func (table *EndpointTable) Snapshot() []DCEndpoint {
	if table == nil {
		return nil
	}
	table.mu.RLock()
	endpoints := make([]DCEndpoint, 0, len(table.endpoints))
	for _, endpoint := range table.endpoints {
		endpoints = append(endpoints, endpoint)
	}
	table.mu.RUnlock()
	sort.Slice(endpoints, func(left, right int) bool { return endpoints[left].ID < endpoints[right].ID })
	return endpoints
}

func validEndpoint(endpoint DCEndpoint) bool {
	if endpoint.ID <= 0 || endpoint.Address == "" {
		return false
	}
	_, port, err := net.SplitHostPort(endpoint.Address)
	if err != nil || port == "" {
		return false
	}
	value, err := strconv.Atoi(port)
	return err == nil && value > 0 && value <= 65535
}
