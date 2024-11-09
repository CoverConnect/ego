package ego

import "github.com/CoverConnect/ego/pkg/api"

func init() {
	go api.Serve()
}
