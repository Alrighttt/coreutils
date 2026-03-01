package syncer_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"go.sia.tech/core/gateway"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/coreutils/syncer"
	"go.sia.tech/coreutils/testutil"
	"go.sia.tech/coreutils/testutil/certs"
	"go.uber.org/zap/zaptest"
)

func newWebTransportTestSyncer(t testing.TB, opts ...syncer.Option) (*syncer.Syncer, *chain.Manager) {
	n, genesis := testutil.Network()
	store, tipState, err := chain.NewDBStore(chain.NewMemDB(), n, genesis, nil)
	if err != nil {
		t.Fatal(err)
	}
	cm := chain.NewManager(store, tipState)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })

	c, err := syncer.NewWebTransportConnector(pc, gateway.Header{
		GenesisID:  genesis.ID(),
		UniqueID:   gateway.GenerateUniqueID(),
		NetAddress: pc.LocalAddr().String(),
	}, &certs.EphemeralCertManager{}, 10*time.Second,
		syncer.WithWebTransportLogger(zaptest.NewLogger(t)),
		syncer.WithWebTransportTLSConfig(&tls.Config{InsecureSkipVerify: true}),
	)
	if err != nil {
		t.Fatal(err)
	}

	opts = append([]syncer.Option{syncer.WithSyncInterval(100 * time.Millisecond)}, opts...)
	s := syncer.New(c, cm, testutil.NewEphemeralPeerStore(), opts...)
	go s.Run()
	t.Cleanup(func() { s.Close() })
	return s, cm
}

func newDualStackTestSyncer(t testing.TB, opts ...syncer.Option) (*syncer.Syncer, *chain.Manager, *syncer.MultiConnector) {
	n, genesis := testutil.Network()
	store, tipState, err := chain.NewDBStore(chain.NewMemDB(), n, genesis, nil)
	if err != nil {
		t.Fatal(err)
	}
	cm := chain.NewManager(store, tipState)

	// TCP connector
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	uid := gateway.GenerateUniqueID()
	tcpC := syncer.NewGatewayConnector(l, gateway.Header{
		GenesisID:  genesis.ID(),
		UniqueID:   uid,
		NetAddress: l.Addr().String(),
	}, nil, 10*time.Second)

	// WebTransport connector
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	wtC, err := syncer.NewWebTransportConnector(pc, gateway.Header{
		GenesisID:  genesis.ID(),
		UniqueID:   uid,
		NetAddress: pc.LocalAddr().String(),
	}, &certs.EphemeralCertManager{}, 10*time.Second,
		syncer.WithWebTransportLogger(zaptest.NewLogger(t)),
		syncer.WithWebTransportTLSConfig(&tls.Config{InsecureSkipVerify: true}),
	)
	if err != nil {
		t.Fatal(err)
	}

	mc := syncer.NewMultiConnector(tcpC, wtC)
	opts = append([]syncer.Option{syncer.WithSyncInterval(100 * time.Millisecond)}, opts...)
	s := syncer.New(mc, cm, testutil.NewEphemeralPeerStore(), opts...)
	go s.Run()
	t.Cleanup(func() { s.Close() })
	return s, cm, mc
}

func TestWebTransportSync(t *testing.T) {
	log := zaptest.NewLogger(t)

	s1, cm1 := newWebTransportTestSyncer(t, syncer.WithLogger(log.Named("s1")))
	s2, cm2 := newWebTransportTestSyncer(t, syncer.WithLogger(log.Named("s2")))

	// mine blocks on s1
	testutil.MineBlocks(t, cm1, types.VoidAddress, 5)

	// connect s2 to s1 via WebTransport
	if _, err := s2.Connect(context.Background(), s1.Addr()); err != nil {
		t.Fatal(err)
	}

	synced(t, cm1, cm2)
	if cm1.Tip() != cm2.Tip() {
		t.Fatal("tips should be equal after sync")
	}
}

func TestMultiConnectorSync(t *testing.T) {
	log := zaptest.NewLogger(t)

	// dual-stack syncer (TCP + WebTransport)
	ds, dsCM, mc := newDualStackTestSyncer(t, syncer.WithLogger(log.Named("dual")))

	// mine blocks on dual-stack
	testutil.MineBlocks(t, dsCM, types.VoidAddress, 5)

	// TCP-only syncer connects to dual-stack via TCP
	tcpS, tcpCM := newTestSyncer(t, syncer.WithLogger(log.Named("tcp")))
	tcpAddr := ds.Addr() // MultiConnector.Addr() returns TCP address
	if _, err := tcpS.Connect(context.Background(), tcpAddr); err != nil {
		t.Fatal(err)
	}
	synced(t, dsCM, tcpCM)

	// WebTransport-only syncer connects to dual-stack via WebTransport
	wtS, wtCM := newWebTransportTestSyncer(t, syncer.WithLogger(log.Named("wt")))
	wtAddr := mc.Addrs()[1] // second connector is WebTransport
	if _, err := wtS.Connect(context.Background(), wtAddr); err != nil {
		t.Fatal(err)
	}
	synced(t, dsCM, wtCM)
}
