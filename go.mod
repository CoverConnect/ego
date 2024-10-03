module github.com/CoverConnect/ego

go 1.22.5

replace github.com/go-delve/delve => ./depp/delve

require (
	github.com/cilium/ebpf v0.16.0
	go.opentelemetry.io/otel v1.30.0
	go.opentelemetry.io/otel/exporters/stdout/stdouttrace v1.30.0
	go.opentelemetry.io/otel/sdk v1.30.0
	go.opentelemetry.io/otel/trace v1.30.0
)

require (
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	go.opentelemetry.io/otel/metric v1.30.0 // indirect
	golang.org/x/net v0.29.0 // indirect
)

require (
	github.com/go-delve/delve v0.0.0-00010101000000-000000000000
	github.com/hashicorp/golang-lru v1.0.2 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	golang.org/x/arch v0.10.0
	golang.org/x/exp v0.0.0-20240904232852-e7e105dedf7e // indirect
	golang.org/x/sys v0.25.0 // indirect
)
