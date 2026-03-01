package syncer

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
	"go.sia.tech/core/gateway"
	"go.uber.org/zap"
)

// WebTransportEndpoint is the HTTP path used for WebTransport syncer
// connections.
const WebTransportEndpoint = "/sia/syncer"

// A CertManager provides TLS certificates for QUIC/WebTransport listeners.
type CertManager interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// wtStream wraps a *webtransport.Stream as a net.Conn by adding
// LocalAddr/RemoteAddr and draining on close for clean QUIC teardown.
type wtStream struct {
	*webtransport.Stream
	localAddr, remoteAddr net.Addr
}

func (s *wtStream) LocalAddr() net.Addr  { return s.localAddr }
func (s *wtStream) RemoteAddr() net.Addr { return s.remoteAddr }
func (s *wtStream) Close() error {
	err := s.Stream.Close()
	// drain remaining data so the peer sees a clean close
	io.CopyN(io.Discard, s, 4096)
	return err
}

func wrapWTStream(s *webtransport.Stream, sess *webtransport.Session) net.Conn {
	return &wtStream{
		Stream:     s,
		localAddr:  sess.LocalAddr(),
		remoteAddr: sess.RemoteAddr(),
	}
}

// WebTransportPeerTransport implements PeerTransport over a WebTransport
// session.
type WebTransportPeerTransport struct {
	sess     *webtransport.Session
	addr     string
	version  string
	uniqueID gateway.UniqueID
}

// Addr returns the peer's reported dialback address.
func (t *WebTransportPeerTransport) Addr() string { return t.addr }

// Version returns the peer's reported version.
func (t *WebTransportPeerTransport) Version() string { return t.version }

// UniqueID returns the peer's unique identifier.
func (t *WebTransportPeerTransport) UniqueID() gateway.UniqueID { return t.uniqueID }

// DialStream opens a new bidirectional stream to the peer.
func (t *WebTransportPeerTransport) DialStream() (*gateway.Stream, error) {
	s, err := t.sess.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}
	return gateway.NewStream(wrapWTStream(s, t.sess)), nil
}

// AcceptStream accepts an incoming bidirectional stream from the peer.
func (t *WebTransportPeerTransport) AcceptStream() (*gateway.Stream, error) {
	s, err := t.sess.AcceptStream(context.Background())
	if err != nil {
		return nil, err
	}
	return gateway.NewStream(wrapWTStream(s, t.sess)), nil
}

// Close closes the WebTransport session.
func (t *WebTransportPeerTransport) Close() error {
	return t.sess.CloseWithError(0, "")
}

// WebTransportConnector implements Connector using QUIC/HTTP3/WebTransport.
type WebTransportConnector struct {
	ql     *quic.Listener
	wts    *webtransport.Server
	header gateway.Header

	timeout  time.Duration
	tlsConf  *tls.Config // for dialing
	log      *zap.Logger
	sessCh   chan *webtransport.Session
	closed   chan struct{}
	lisAddr  string
	serveDone chan struct{}
}

// NewWebTransportConnector returns a Connector that listens for inbound
// WebTransport connections and dials outbound ones, performing the gateway
// handshake on each.
func NewWebTransportConnector(
	pc net.PacketConn,
	header gateway.Header,
	certs CertManager,
	timeout time.Duration,
	opts ...WebTransportOption,
) (*WebTransportConnector, error) {
	cfg := webTransportConfig{
		log:     zap.NewNop(),
		tlsConf: &tls.Config{},
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	ql, err := quic.Listen(pc, &tls.Config{
		GetCertificate: certs.GetCertificate,
		NextProtos:     []string{http3.NextProtoH3},
	}, &quic.Config{
		EnableDatagrams:                  true,
		KeepAlivePeriod:                  30 * time.Second,
		MaxIdleTimeout:                   30 * time.Minute,
		MaxIncomingStreams:               100000,
		EnableStreamResetPartialDelivery: true,
	})
	if err != nil {
		return nil, err
	}

	c := &WebTransportConnector{
		ql:        ql,
		header:    header,
		timeout:   timeout,
		tlsConf:   cfg.tlsConf,
		log:       cfg.log,
		sessCh:    make(chan *webtransport.Session, 64),
		closed:    make(chan struct{}),
		lisAddr:   pc.LocalAddr().String(),
		serveDone: make(chan struct{}),
	}

	mux := http.NewServeMux()
	c.wts = &webtransport.Server{
		H3: &http3.Server{
			Handler: mux,
		},
		CheckOrigin: func(r *http.Request) bool {
			c.log.Debug("webtransport CheckOrigin called",
				zap.String("origin", r.Header.Get("Origin")),
				zap.String("host", r.Host),
				zap.String("method", r.Method),
				zap.String("url", r.URL.String()))
			return true
		},
	}
	webtransport.ConfigureHTTP3Server(c.wts.H3)
	c.log.Debug("webtransport server configured",
		zap.String("listenAddr", c.lisAddr),
		zap.String("endpoint", WebTransportEndpoint))

	// catch-all handler to log unexpected requests
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		c.log.Debug("webtransport: unmatched HTTP request",
			zap.String("method", r.Method),
			zap.String("url", r.URL.String()),
			zap.String("proto", r.Proto),
			zap.String("host", r.Host))
		http.NotFound(w, r)
	})

	mux.HandleFunc(WebTransportEndpoint, func(w http.ResponseWriter, r *http.Request) {
		c.log.Debug("webtransport handler: request received",
			zap.String("method", r.Method),
			zap.String("url", r.URL.String()),
			zap.String("proto", r.Proto),
			zap.String("host", r.Host),
			zap.String("remoteAddr", r.RemoteAddr))
		sess, err := c.wts.Upgrade(w, r)
		if err != nil {
			c.log.Debug("webtransport upgrade failed", zap.Error(err),
				zap.String("method", r.Method),
				zap.String("url", r.URL.String()),
				zap.String("proto", r.Proto))
			return
		}
		c.log.Debug("webtransport session established",
			zap.String("remoteAddr", sess.RemoteAddr().String()))
		select {
		case c.sessCh <- sess:
		case <-c.closed:
			sess.CloseWithError(0, "closing")
		}
	})

	go c.serveLoop()
	return c, nil
}

// NewWebTransportConnectorFromServer creates a WebTransportConnector that
// receives sessions from an existing WebTransport server rather than managing
// its own QUIC listener. It registers a handler at WebTransportEndpoint on the
// provided mux. Outbound Dial still works independently.
func NewWebTransportConnectorFromServer(
	wts *webtransport.Server,
	mux *http.ServeMux,
	lisAddr string,
	header gateway.Header,
	timeout time.Duration,
	opts ...WebTransportOption,
) *WebTransportConnector {
	cfg := webTransportConfig{
		log:     zap.NewNop(),
		tlsConf: &tls.Config{},
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	c := &WebTransportConnector{
		// ql and wts are nil — we don't own them
		header:  header,
		timeout: timeout,
		tlsConf: cfg.tlsConf,
		log:     cfg.log,
		sessCh:  make(chan *webtransport.Session, 64),
		closed:  make(chan struct{}),
		lisAddr: lisAddr,
	}

	mux.HandleFunc(WebTransportEndpoint, func(w http.ResponseWriter, r *http.Request) {
		c.log.Debug("webtransport handler: request received",
			zap.String("method", r.Method),
			zap.String("url", r.URL.String()),
			zap.String("proto", r.Proto),
			zap.String("host", r.Host),
			zap.String("remoteAddr", r.RemoteAddr))
		sess, err := wts.Upgrade(w, r)
		if err != nil {
			c.log.Debug("webtransport upgrade failed", zap.Error(err))
			return
		}
		c.log.Debug("webtransport session established",
			zap.String("remoteAddr", sess.RemoteAddr().String()))
		select {
		case c.sessCh <- sess:
		case <-c.closed:
			sess.CloseWithError(0, "closing")
		}
	})

	return c
}

func (c *WebTransportConnector) serveLoop() {
	defer close(c.serveDone)
	c.log.Debug("webtransport serve loop started")
	for {
		conn, err := c.ql.Accept(context.Background())
		if err != nil {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, quic.ErrServerClosed) {
				c.log.Debug("failed to accept QUIC connection", zap.Error(err))
			}
			return
		}
		proto := conn.ConnectionState().TLS.NegotiatedProtocol
		c.log.Debug("webtransport: accepted QUIC connection",
			zap.String("remoteAddr", conn.RemoteAddr().String()),
			zap.String("alpn", proto))
		go func() {
			defer conn.CloseWithError(0, "")
			if err := c.wts.ServeQUICConn(conn); err != nil {
				c.log.Debug("failed to serve webtransport connection",
					zap.Error(err),
					zap.String("remoteAddr", conn.RemoteAddr().String()))
			} else {
				c.log.Debug("webtransport: ServeQUICConn completed",
					zap.String("remoteAddr", conn.RemoteAddr().String()))
			}
		}()
	}
}

// Accept blocks until an inbound peer connects via WebTransport, performs the
// gateway handshake, and returns the transport. Per-session handshake failures
// are logged and retried; only permanent errors (context cancelled, connector
// closed) are returned.
func (c *WebTransportConnector) Accept(ctx context.Context) (PeerTransport, string, error) {
	for {
		var sess *webtransport.Session
		select {
		case sess = <-c.sessCh:
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-c.closed:
			return nil, "", net.ErrClosed
		}

		remoteAddr := sess.RemoteAddr().String()
		c.log.Debug("webtransport accept: got session, waiting for handshake stream",
			zap.String("remoteAddr", remoteAddr))

		// perform handshake on the first stream (opened by the dialer)
		hsCtx, cancel := context.WithTimeout(ctx, c.timeout)
		s, err := sess.AcceptStream(hsCtx)
		cancel()
		if err != nil {
			c.log.Debug("webtransport accept: AcceptStream failed",
				zap.String("remoteAddr", remoteAddr), zap.Error(err))
			sess.CloseWithError(1, "handshake failed")
			continue // retry with next session
		}

		c.log.Debug("webtransport accept: got handshake stream, performing handshake",
			zap.String("remoteAddr", remoteAddr))
		conn := wrapWTStream(s, sess)
		conn.SetDeadline(time.Now().Add(c.timeout))
		info, err := gateway.AcceptHandshake(conn, c.header)
		conn.Close()
		if err != nil {
			c.log.Debug("webtransport accept: handshake failed",
				zap.String("remoteAddr", remoteAddr), zap.Error(err))
			sess.CloseWithError(1, "handshake failed")
			continue // retry with next session
		}

		c.log.Debug("webtransport accept: handshake complete",
			zap.String("remoteAddr", remoteAddr),
			zap.String("peerAddr", info.Addr),
			zap.String("peerVersion", info.Version))

		return &WebTransportPeerTransport{
			sess:     sess,
			addr:     info.Addr,
			version:  info.Version,
			uniqueID: info.UniqueID,
		}, sess.RemoteAddr().String(), nil
	}
}

// Dial creates an outbound WebTransport connection to addr, performs the
// gateway handshake, and returns the transport. addr should be a URL like
// "wss://host:port/sia/syncer" or just "host:port" (the endpoint path is
// appended automatically).
func (c *WebTransportConnector) Dial(ctx context.Context, addr string) (PeerTransport, string, error) {
	url := addr
	if !hasScheme(addr) {
		url = "https://" + addr + WebTransportEndpoint
	}

	d := webtransport.Dialer{
		TLSClientConfig: c.tlsConf,
	}
	_, sess, err := d.Dial(ctx, url, nil)
	if err != nil {
		return nil, "", err
	}

	// open a stream for the handshake
	s, err := sess.OpenStreamSync(ctx)
	if err != nil {
		sess.CloseWithError(1, "handshake failed")
		return nil, "", err
	}
	conn := wrapWTStream(s, sess)
	conn.SetDeadline(time.Now().Add(c.timeout))
	info, err := gateway.DialHandshake(conn, c.header)
	conn.Close()
	if err != nil {
		sess.CloseWithError(1, "handshake failed")
		return nil, "", err
	}

	return &WebTransportPeerTransport{
		sess:     sess,
		addr:     info.Addr,
		version:  info.Version,
		uniqueID: info.UniqueID,
	}, sess.RemoteAddr().String(), nil
}

// Addr returns the WebTransport listener address as an https:// URL.
func (c *WebTransportConnector) Addr() string {
	return "https://" + c.lisAddr + WebTransportEndpoint
}

// Close closes the QUIC listener and WebTransport server. In shared mode
// (created via NewWebTransportConnectorFromServer), only the session channel
// is closed — the caller owns the listener and server.
func (c *WebTransportConnector) Close() error {
	select {
	case <-c.closed:
		return nil
	default:
		close(c.closed)
	}
	if c.ql == nil {
		return nil // shared mode — we don't own the listener
	}
	err := c.ql.Close()
	c.wts.Close()
	<-c.serveDone
	return err
}

func hasScheme(addr string) bool {
	for i, c := range addr {
		if c == ':' && i > 0 {
			return i+2 < len(addr) && addr[i+1] == '/' && addr[i+2] == '/'
		}
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.') {
			return false
		}
	}
	return false
}

type webTransportConfig struct {
	log     *zap.Logger
	tlsConf *tls.Config
}

// A WebTransportOption configures a WebTransportConnector.
type WebTransportOption func(*webTransportConfig)

// WithWebTransportLogger sets the logger for the WebTransport connector.
func WithWebTransportLogger(log *zap.Logger) WebTransportOption {
	return func(c *webTransportConfig) {
		c.log = log
	}
}

// WithWebTransportTLSConfig sets the TLS client configuration used when
// dialing outbound WebTransport connections.
func WithWebTransportTLSConfig(tc *tls.Config) WebTransportOption {
	return func(c *webTransportConfig) {
		c.tlsConf = tc
	}
}
