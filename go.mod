module github.com/CoverConnect/ego

go 1.22.5

replace github.com/go-delve/delve => ./depp/delve

require (
	github.com/cilium/ebpf v0.11.0
	github.com/go-delve/delve v0.0.0-00010101000000-000000000000
)

require (
	github.com/hashicorp/golang-lru v1.0.2 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	golang.org/x/arch v0.6.0 // indirect
	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect
	golang.org/x/sys v0.17.0 // indirect
)
