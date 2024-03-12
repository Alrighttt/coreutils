package syncer

import (
	"errors"
	"fmt"

	"go.sia.tech/core/consensus"
)

const (
	// NetworkAnagami is the name of the Anagami network.
	NetworkAnagami = "anagami"
	// NetworkMainnet is the name of the Mainnet network.
	NetworkMainnet = "mainnet"
	// NetworkZen is the name of the Zen network.
	NetworkZen = "zen"
)

var (
	// ErrUnknownNetwork is returned when trying to boostrap a network with a
	// name that is not recognized.
	ErrUnknownNetwork = errors.New("unknown network")
)
var (
	// AnagamiBootstrapPeers is a list of peers for the Anagami network.
	AnagamiBootstrapPeers = []string{
		"147.135.16.182:9781",
		"98.180.237.163:9981",
		"98.180.237.163:11981",
		"98.180.237.163:10981",
		"94.130.139.59:9801",
		"84.86.11.238:9801",
		"69.131.14.86:9981",
		"68.108.89.92:9981",
		"62.30.63.93:9981",
		"46.173.150.154:9111",
		"195.252.198.117:9981",
		"174.174.206.214:9981",
		"172.58.232.54:9981",
		"172.58.229.31:9981",
		"172.56.200.90:9981",
		"172.56.162.155:9981",
		"163.172.13.180:9981",
		"154.47.25.194:9981",
		"138.201.19.49:9981",
		"100.34.20.44:9981",
	}

	// MainnetBootstrapPeers is a list of peers for the Mainnet network.
	MainnetBootstrapPeers = []string{
		"108.227.62.195:9981",
		"139.162.81.190:9991",
		"144.217.7.188:9981",
		"147.182.196.252:9981",
		"15.235.85.30:9981",
		"167.235.234.84:9981",
		"173.235.144.230:9981",
		"198.98.53.144:7791",
		"199.27.255.169:9981",
		"2.136.192.200:9981",
		"213.159.50.43:9981",
		"24.253.116.61:9981",
		"46.249.226.103:9981",
		"5.165.236.113:9981",
		"5.252.226.131:9981",
		"54.38.120.222:9981",
		"62.210.136.25:9981",
		"63.135.62.123:9981",
		"65.21.93.245:9981",
		"75.165.149.114:9981",
		"77.51.200.125:9981",
		"81.6.58.121:9981",
		"83.194.193.156:9981",
		"84.39.246.63:9981",
		"87.99.166.34:9981",
		"91.214.242.11:9981",
		"93.105.88.181:9981",
		"93.180.191.86:9981",
		"94.130.220.162:9981",
	}

	// ZenBootstrapPeers is a list of peers for the Zen network.
	ZenBootstrapPeers = []string{
		"147.135.16.182:9881",
		"147.135.39.109:9881",
		"51.81.208.10:9881",
	}
)

// Bootstrap will add the bootstrap peers for the given network to the store.
func Bootstrap(n consensus.Network, ps PeerStore) error {
	var bootstrapPeers []string
	switch n.Name {
	case NetworkAnagami:
		bootstrapPeers = AnagamiBootstrapPeers
	case NetworkMainnet:
		bootstrapPeers = MainnetBootstrapPeers
	case NetworkZen:
		bootstrapPeers = ZenBootstrapPeers
	default:
		return fmt.Errorf("%w '%s'", ErrUnknownNetwork, n.Name)
	}

	for _, addr := range bootstrapPeers {
		if err := ps.AddPeer(addr); err != nil {
			return err
		}
	}
	return nil
}
