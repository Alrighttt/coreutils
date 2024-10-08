module go.sia.tech/coreutils

go 1.21.8

require (
	go.etcd.io/bbolt v1.3.10
	go.sia.tech/core v0.4.4-0.20240814175157-ebc804c7119c
	go.uber.org/zap v1.27.0
	golang.org/x/crypto v0.26.0
	lukechampine.com/frand v1.4.2
)

require (
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da // indirect
	go.sia.tech/mux v1.2.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/sys v0.24.0 // indirect
)

replace go.sia.tech/core => github.com/alrighttt/core v0.0.0-20240817151302-1b7d22764744
// replace go.sia.tech/core => ../core