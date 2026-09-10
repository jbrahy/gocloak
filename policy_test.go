package gocloak

import (
	"net/netip"
	"sync"
	"testing"
)

func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

func mustAddrPort(s string) netip.AddrPort {
	a, err := netip.ParseAddrPort(s)
	if err != nil {
		panic(err)
	}
	return a
}

// TestPolicyResolve covers the required table cases (unknown peer, unknown
// service, cross-peer access, empty allow map) plus the happy path and the
// same-service-name-different-backend isolation case.
func TestPolicyResolve(t *testing.T) {
	peerA := mustAddr("10.99.0.2")
	peerB := mustAddr("10.99.0.3")
	peerEmpty := mustAddr("10.99.0.4")
	unknownPeer := mustAddr("10.99.0.99")

	backendAPrimary := mustAddrPort("192.0.2.10:3306")
	backendAShared := mustAddrPort("192.0.2.11:6379")
	backendBCache := mustAddrPort("192.0.2.12:6379")
	backendBShared := mustAddrPort("192.0.2.13:6379")

	pol, err := NewPolicy([]PeerPolicy{
		{
			TunnelIP: peerA,
			Allow: map[string]netip.AddrPort{
				"primary-db": backendAPrimary,
				"shared-svc": backendAShared,
			},
		},
		{
			TunnelIP: peerB,
			Allow: map[string]netip.AddrPort{
				"cache":      backendBCache,
				"shared-svc": backendBShared,
			},
		},
		{
			TunnelIP: peerEmpty,
			Allow:    map[string]netip.AddrPort{},
		},
	})
	if err != nil {
		t.Fatalf("NewPolicy: unexpected error: %v", err)
	}

	tests := []struct {
		name        string
		peer        netip.Addr
		service     string
		wantBackend netip.AddrPort
		wantOK      bool
	}{
		{
			name:        "happy path resolves exact backend",
			peer:        peerA,
			service:     "primary-db",
			wantBackend: backendAPrimary,
			wantOK:      true,
		},
		{
			name:    "unknown peer denies",
			peer:    unknownPeer,
			service: "primary-db",
			wantOK:  false,
		},
		{
			name:    "unknown service for known peer denies",
			peer:    peerA,
			service: "cache",
			wantOK:  false,
		},
		{
			name:    "cross-peer access denies: A cannot reach B's service",
			peer:    peerA,
			service: "cache",
			wantOK:  false,
		},
		{
			name:    "cross-peer access denies: B cannot reach A's service",
			peer:    peerB,
			service: "primary-db",
			wantOK:  false,
		},
		{
			name:    "empty allow map denies everything",
			peer:    peerEmpty,
			service: "primary-db",
			wantOK:  false,
		},
		{
			name:        "shared service name resolves to A's own backend",
			peer:        peerA,
			service:     "shared-svc",
			wantBackend: backendAShared,
			wantOK:      true,
		},
		{
			name:        "shared service name resolves to B's own backend",
			peer:        peerB,
			service:     "shared-svc",
			wantBackend: backendBShared,
			wantOK:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := pol.Resolve(tc.peer, tc.service)
			if ok != tc.wantOK {
				t.Fatalf("Resolve(%v, %q) ok = %v, want %v", tc.peer, tc.service, ok, tc.wantOK)
			}
			if ok && got != tc.wantBackend {
				t.Fatalf("Resolve(%v, %q) = %v, want %v", tc.peer, tc.service, got, tc.wantBackend)
			}
		})
	}
}

// TestPolicyResolve_CaseSensitive asserts that a lookup with different case
// does not match a stored grant. ValidServiceName already forbids uppercase
// in stored grants, so this asserts the lookup path never case-folds.
func TestPolicyResolve_CaseSensitive(t *testing.T) {
	peerA := mustAddr("10.99.0.2")
	backend := mustAddrPort("192.0.2.10:3306")

	pol, err := NewPolicy([]PeerPolicy{
		{
			TunnelIP: peerA,
			Allow: map[string]netip.AddrPort{
				"primary-db": backend,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewPolicy: unexpected error: %v", err)
	}

	if _, ok := pol.Resolve(peerA, "Primary-DB"); ok {
		t.Fatalf("Resolve with mismatched case must deny, got allow")
	}
	if _, ok := pol.Resolve(peerA, "PRIMARY-DB"); ok {
		t.Fatalf("Resolve with mismatched case must deny, got allow")
	}
}

// TestPolicy_NewRejects covers construction-time validation: a Policy value
// that exists must be safe to consult, so bad input must fail loudly here
// rather than at lookup time.
func TestPolicy_NewRejects(t *testing.T) {
	validIP := mustAddr("10.99.0.2")
	otherIP := mustAddr("10.99.0.3")
	validBackend := mustAddrPort("192.0.2.10:3306")

	tests := []struct {
		name  string
		peers []PeerPolicy
	}{
		{
			name: "duplicate tunnel ip across two peers",
			peers: []PeerPolicy{
				{TunnelIP: validIP, Allow: map[string]netip.AddrPort{"a": validBackend}},
				{TunnelIP: validIP, Allow: map[string]netip.AddrPort{"b": validBackend}},
			},
		},
		{
			name: "invalid service name: uppercase",
			peers: []PeerPolicy{
				{TunnelIP: validIP, Allow: map[string]netip.AddrPort{"Primary-DB": validBackend}},
			},
		},
		{
			name: "invalid service name: empty",
			peers: []PeerPolicy{
				{TunnelIP: validIP, Allow: map[string]netip.AddrPort{"": validBackend}},
			},
		},
		{
			name: "zero tunnel ip",
			peers: []PeerPolicy{
				{TunnelIP: netip.Addr{}, Allow: map[string]netip.AddrPort{"a": validBackend}},
			},
		},
		{
			name: "unspecified tunnel ip",
			peers: []PeerPolicy{
				{TunnelIP: netip.IPv4Unspecified(), Allow: map[string]netip.AddrPort{"a": validBackend}},
			},
		},
		{
			name: "malformed backend address: zero value",
			peers: []PeerPolicy{
				{TunnelIP: validIP, Allow: map[string]netip.AddrPort{"a": netip.AddrPort{}}},
			},
		},
		{
			name: "malformed backend address: zero port",
			peers: []PeerPolicy{
				{TunnelIP: validIP, Allow: map[string]netip.AddrPort{"a": netip.AddrPortFrom(mustAddr("192.0.2.10"), 0)}},
			},
		},
		{
			name: "one bad peer among good peers still fails the whole construction",
			peers: []PeerPolicy{
				{TunnelIP: validIP, Allow: map[string]netip.AddrPort{"a": validBackend}},
				{TunnelIP: otherIP, Allow: map[string]netip.AddrPort{"Bad-Name": validBackend}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pol, err := NewPolicy(tc.peers)
			if err == nil {
				t.Fatalf("NewPolicy(%s): expected error, got nil (policy=%+v)", tc.name, pol)
			}
			if pol != nil {
				t.Fatalf("NewPolicy(%s): expected nil policy on error, got %+v", tc.name, pol)
			}
		})
	}
}

// TestPolicy_NewAccepts is the construction-side happy path: valid input
// builds a usable Policy.
func TestPolicy_NewAccepts(t *testing.T) {
	pol, err := NewPolicy([]PeerPolicy{
		{
			TunnelIP: mustAddr("10.99.0.2"),
			Allow: map[string]netip.AddrPort{
				"primary-db": mustAddrPort("192.0.2.10:3306"),
			},
		},
	})
	if err != nil {
		t.Fatalf("NewPolicy: unexpected error: %v", err)
	}
	if pol == nil {
		t.Fatalf("NewPolicy: expected non-nil policy")
	}
}

// TestPolicy_NewEmpty asserts that an empty peer list is valid and denies
// everything, since default deny is the whole point.
func TestPolicy_NewEmpty(t *testing.T) {
	pol, err := NewPolicy(nil)
	if err != nil {
		t.Fatalf("NewPolicy(nil): unexpected error: %v", err)
	}
	if _, ok := pol.Resolve(mustAddr("10.99.0.2"), "primary-db"); ok {
		t.Fatalf("Resolve against empty policy must deny, got allow")
	}
}

// TestPolicyResolve_ConcurrentReads exercises Resolve from many goroutines
// against a single Policy value, to be run with -race. The Policy must be
// safe to share across goroutines by construction, since task 7's server
// reads it concurrently while task 5's hot reload swaps it out.
func TestPolicyResolve_ConcurrentReads(t *testing.T) {
	peerA := mustAddr("10.99.0.2")
	peerB := mustAddr("10.99.0.3")
	backendA := mustAddrPort("192.0.2.10:3306")
	backendB := mustAddrPort("192.0.2.11:6379")

	pol, err := NewPolicy([]PeerPolicy{
		{TunnelIP: peerA, Allow: map[string]netip.AddrPort{"primary-db": backendA}},
		{TunnelIP: peerB, Allow: map[string]netip.AddrPort{"cache": backendB}},
	})
	if err != nil {
		t.Fatalf("NewPolicy: unexpected error: %v", err)
	}

	var wg sync.WaitGroup
	const goroutines = 50
	const iterations = 200
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				if i%2 == 0 {
					got, ok := pol.Resolve(peerA, "primary-db")
					if !ok || got != backendA {
						t.Errorf("Resolve(peerA, primary-db) = %v, %v; want %v, true", got, ok, backendA)
						return
					}
					if _, ok := pol.Resolve(peerA, "cache"); ok {
						t.Errorf("Resolve(peerA, cache) allowed, want deny")
						return
					}
				} else {
					got, ok := pol.Resolve(peerB, "cache")
					if !ok || got != backendB {
						t.Errorf("Resolve(peerB, cache) = %v, %v; want %v, true", got, ok, backendB)
						return
					}
					if _, ok := pol.Resolve(peerB, "primary-db"); ok {
						t.Errorf("Resolve(peerB, primary-db) allowed, want deny")
						return
					}
				}
			}
		}(i)
	}
	wg.Wait()
}
