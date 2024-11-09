package main

import "github.com/CoverConnect/ego/pkg/api"

func init() {
	go api.Serve()
}
