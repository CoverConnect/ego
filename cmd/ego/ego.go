package ego

import (
	"flag"

	"github.com/CoverConnect/ego/pkg/api"
	. "github.com/CoverConnect/ego/pkg/config"

)


var configPathPtr = flag.String("configFilePath", GetEnv("EGO_CONFIG_FILE_PATH", "/etc/config/config.yaml"), "Location of the ego server configuration file")

func init() {
	InitConfig(*configPathPtr)
	go api.Serve()
}
