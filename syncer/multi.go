package syncer

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
)

type acceptResult struct {
	transport PeerTransport
	connAddr  string
	err       error
}

// A MultiConnector multiplexes multiple Connectors, accepting inbound
// connections from all of them and dispatching outbound connections based on
// address format.
type MultiConnector struct {
	connectors []Connector
	acceptCh   chan acceptResult
	closeOnce  sync.Once
	closed     chan struct{}
	wg         sync.WaitGroup
}

// NewMultiConnector returns a Connector that fans in Accept from all provided
// connectors and dispatches Dial based on address format.
func NewMultiConnector(connectors ...Connector) *MultiConnector {
	mc := &MultiConnector{
		connectors: connectors,
		acceptCh:   make(chan acceptResult, 1),
		closed:     make(chan struct{}),
	}
	for _, c := range connectors {
		mc.wg.Add(1)
		go mc.acceptLoop(c)
	}
	return mc
}

func (mc *MultiConnector) acceptLoop(c Connector) {
	defer mc.wg.Done()
	for {
		t, addr, err := c.Accept(context.Background())
		select {
		case mc.acceptCh <- acceptResult{t, addr, err}:
			if err != nil {
				return
			}
		case <-mc.closed:
			if t != nil {
				t.Close()
			}
			return
		}
	}
}

// Accept blocks until an inbound peer connects on any sub-connector.
func (mc *MultiConnector) Accept(ctx context.Context) (PeerTransport, string, error) {
	select {
	case r := <-mc.acceptCh:
		return r.transport, r.connAddr, r.err
	case <-ctx.Done():
		return nil, "", ctx.Err()
	case <-mc.closed:
		return nil, "", net.ErrClosed
	}
}

// Dial dispatches to the appropriate sub-connector based on address format.
// Addresses starting with "wss://" or "https://" are routed to the first
// WebTransportConnector; all others go to the first GatewayConnector.
func (mc *MultiConnector) Dial(ctx context.Context, addr string) (PeerTransport, string, error) {
	c := mc.connectorForAddr(addr)
	if c == nil {
		return nil, "", errors.New("no connector available for address: " + addr)
	}
	return c.Dial(ctx, addr)
}

func (mc *MultiConnector) connectorForAddr(addr string) Connector {
	isWT := strings.HasPrefix(addr, "https://")
	for _, c := range mc.connectors {
		if isWT {
			if _, ok := c.(*WebTransportConnector); ok {
				return c
			}
		} else {
			if _, ok := c.(*GatewayConnector); ok {
				return c
			}
		}
	}
	// fallback to first connector
	if len(mc.connectors) > 0 {
		return mc.connectors[0]
	}
	return nil
}

// Addr returns the address of the first connector (typically TCP for backward
// compatibility).
func (mc *MultiConnector) Addr() string {
	if len(mc.connectors) > 0 {
		return mc.connectors[0].Addr()
	}
	return ""
}

// Addrs returns the addresses of all sub-connectors.
func (mc *MultiConnector) Addrs() []string {
	addrs := make([]string, len(mc.connectors))
	for i, c := range mc.connectors {
		addrs[i] = c.Addr()
	}
	return addrs
}

// Close closes all sub-connectors.
func (mc *MultiConnector) Close() error {
	mc.closeOnce.Do(func() { close(mc.closed) })
	var errs []error
	for _, c := range mc.connectors {
		if err := c.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	mc.wg.Wait()
	return errors.Join(errs...)
}
