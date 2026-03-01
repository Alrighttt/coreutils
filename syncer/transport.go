package syncer

import (
	"context"
	"net"
	"time"

	"go.sia.tech/core/gateway"
)

// A PeerTransport provides multiplexed streams to a connected peer.
type PeerTransport interface {
	// Addr returns the peer's reported dialback address.
	Addr() string
	// Version returns the peer's reported version string.
	Version() string
	// UniqueID returns the peer's unique identifier.
	UniqueID() gateway.UniqueID
	// DialStream opens a new multiplexed stream to the peer.
	DialStream() (*gateway.Stream, error)
	// AcceptStream accepts an incoming multiplexed stream from the peer.
	AcceptStream() (*gateway.Stream, error)
	// Close closes the transport and its underlying connection.
	Close() error
}

// A Connector handles listening for inbound connections and dialing outbound
// ones. It absorbs the handshake — callers receive an already-established
// PeerTransport.
type Connector interface {
	// Accept blocks until an inbound peer connects and completes the
	// handshake. It returns the transport and the connection address
	// (e.g. IP:port) used for ban checking.
	Accept(ctx context.Context) (PeerTransport, string, error)
	// Dial creates an outbound connection to the given address and completes
	// the handshake. It returns the transport and the connection address.
	Dial(ctx context.Context, addr string) (PeerTransport, string, error)
	// Addr returns the listener address.
	Addr() string
	// Close closes the listener.
	Close() error
}

// GatewayTransport adapts a *gateway.Transport to the PeerTransport interface.
type GatewayTransport struct {
	t *gateway.Transport
}

// NewGatewayTransport wraps a *gateway.Transport as a PeerTransport.
func NewGatewayTransport(t *gateway.Transport) *GatewayTransport {
	return &GatewayTransport{t: t}
}

func (gt *GatewayTransport) Addr() string                            { return gt.t.Addr }
func (gt *GatewayTransport) Version() string                         { return gt.t.Version }
func (gt *GatewayTransport) UniqueID() gateway.UniqueID              { return gt.t.UniqueID }
func (gt *GatewayTransport) DialStream() (*gateway.Stream, error)    { return gt.t.DialStream() }
func (gt *GatewayTransport) AcceptStream() (*gateway.Stream, error)  { return gt.t.AcceptStream() }
func (gt *GatewayTransport) Close() error                            { return gt.t.Close() }

// GatewayConnector implements Connector using TCP connections and the gateway
// handshake protocol.
type GatewayConnector struct {
	l              net.Listener
	d              Dialer
	header         gateway.Header
	connectTimeout time.Duration
}

// NewGatewayConnector returns a Connector that listens for inbound TCP
// connections and dials outbound ones, performing the gateway handshake on each.
func NewGatewayConnector(l net.Listener, header gateway.Header, d Dialer, connectTimeout time.Duration) *GatewayConnector {
	if d == nil {
		d = &net.Dialer{}
	}
	return &GatewayConnector{
		l:              l,
		d:              d,
		header:         header,
		connectTimeout: connectTimeout,
	}
}

// Accept accepts an inbound TCP connection, performs the gateway handshake, and
// returns the resulting transport along with the remote address.
func (c *GatewayConnector) Accept(ctx context.Context) (PeerTransport, string, error) {
	conn, err := c.l.Accept()
	if err != nil {
		return nil, "", err
	}
	conn.SetDeadline(time.Now().Add(c.connectTimeout))
	t, err := gateway.Accept(conn, c.header)
	if err != nil {
		conn.Close()
		return nil, "", err
	}
	conn.SetDeadline(time.Time{})
	return NewGatewayTransport(t), conn.RemoteAddr().String(), nil
}

// Dial dials a TCP connection to addr, performs the gateway handshake, and
// returns the resulting transport along with the remote address.
func (c *GatewayConnector) Dial(ctx context.Context, addr string) (PeerTransport, string, error) {
	conn, err := c.d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, "", err
	}
	conn.SetDeadline(time.Now().Add(c.connectTimeout))
	t, err := gateway.Dial(conn, c.header)
	if err != nil {
		conn.Close()
		return nil, "", err
	}
	conn.SetDeadline(time.Time{})
	return NewGatewayTransport(t), conn.RemoteAddr().String(), nil
}

// Addr returns the listener's address.
func (c *GatewayConnector) Addr() string { return c.l.Addr().String() }

// Close closes the listener.
func (c *GatewayConnector) Close() error { return c.l.Close() }
