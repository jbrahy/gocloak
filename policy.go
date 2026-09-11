package gocloak

import (
	"errors"
	"fmt"
	"net/netip"
)

// peerPolicy describes one peer's tunnel identity and the services it may
// reach. It is the input to newPolicy. config.go (task 5) decodes peers.yaml
// and builds peerPolicy values from it; this package has no dependency on
// config.go or on YAML, so a plain Go literal builds a complete input
// without any fixture file.
type peerPolicy struct {
	// TunnelIP is the peer's WireGuard tunnel address. Per spec section
	// 3.2, cryptokey routing binds this address to the peer's keypair, so
	// it is the authenticated identity a lookup keys off, not a claim the
	// peer makes.
	TunnelIP netip.Addr

	// Allow maps service name to backend address. Absence of a key is
	// denial. There is no wildcard, no CIDR, and no port range: every
	// reachable backend is an explicit entry here.
	Allow map[string]netip.AddrPort
}

// policy is the authorization engine: it answers, for a given peer tunnel IP
// and service name, which backend address (if any) that peer may reach.
//
// A policy is immutable once built by newPolicy: there is no exported
// mutator, no exported map, and no method that hands out a reference to an
// internal map a caller could write through. This makes a *policy value
// safe to share across goroutines by construction, which is required
// because task 7's server reads it concurrently while task 5's hot reload
// swaps a new *policy in atomically.
type policy struct {
	peers map[netip.Addr]map[string]netip.AddrPort
}

// newPolicy builds a policy from peer definitions, validating everything at
// construction time. A *policy that exists is safe to consult: a duplicate
// tunnel IP across two peers, an unspecified or zero tunnel IP, an invalid
// service name, or an invalid backend address all fail construction rather
// than being accepted and only discovered wrong at lookup time. On error,
// newPolicy returns a nil *policy: there is no partially built value to
// accidentally consult.
func newPolicy(peers []peerPolicy) (*policy, error) {
	m := make(map[netip.Addr]map[string]netip.AddrPort, len(peers))

	for _, p := range peers {
		if !p.TunnelIP.IsValid() {
			return nil, errors.New("gocloak: policy: peer has an invalid tunnel ip")
		}
		// Unmap before the unspecified and duplicate checks so
		// 10.99.0.7 and its IPv4-in-IPv6 spelling ::ffff:10.99.0.7 are
		// recognized as the same identity, both here and in Resolve
		// below.
		tunnelIP := p.TunnelIP.Unmap()
		if tunnelIP.IsUnspecified() {
			return nil, fmt.Errorf("gocloak: policy: peer %s: unspecified tunnel ip is not allowed", tunnelIP)
		}
		if _, dup := m[tunnelIP]; dup {
			return nil, fmt.Errorf("gocloak: policy: duplicate tunnel ip %s", tunnelIP)
		}

		allow := make(map[string]netip.AddrPort, len(p.Allow))
		for name, backend := range p.Allow {
			if !ValidServiceName(name) {
				return nil, fmt.Errorf("gocloak: policy: peer %s: invalid service name", tunnelIP)
			}
			if !backend.IsValid() || backend.Port() == 0 || backend.Addr().IsUnspecified() {
				return nil, fmt.Errorf("gocloak: policy: peer %s: service %s: invalid backend address", tunnelIP, name)
			}
			allow[name] = backend
		}
		m[tunnelIP] = allow
	}

	return &policy{peers: m}, nil
}

// Resolve returns the backend address that peerTunnelIP is authorized to
// reach for serviceName, and reports whether that authorization exists. An
// entirely unknown peer and a known peer requesting a service it was not
// granted are indistinguishable in the returned decision: both yield
// (netip.AddrPort{}, false). Callers must check the bool; the zero
// netip.AddrPort is never a valid grant.
func (p *policy) Resolve(peerTunnelIP netip.Addr, serviceName string) (netip.AddrPort, bool) {
	// Unmap so an IPv4-in-IPv6 spelling of a tunnel IP (as conn.RemoteAddr
	// may yield) resolves identically to its IPv4 form, matching how
	// newPolicy normalizes keys at construction.
	allow, ok := p.peers[peerTunnelIP.Unmap()]
	if !ok {
		return netip.AddrPort{}, false
	}
	backend, ok := allow[serviceName]
	if !ok {
		return netip.AddrPort{}, false
	}
	return backend, true
}
