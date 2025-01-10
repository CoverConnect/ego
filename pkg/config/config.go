package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)


var defaultMap = map[string]string {
	"port": "8888",
	"otlpendpoint": "127.0.0.1:1234",
}

var Config = viper.New()

func InitConfig(configPath string) {
	for key, value := range defaultMap {
		Config.SetDefault("ego." + key, value)
	}
	Config.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
    Config.SetEnvKeyReplacer(replacer)
	Config.SetConfigFile(configPath)
	if err := Config.ReadInConfig(); err != nil {
		fmt.Printf("could not read config file: %s\n", err.Error())
	}
}


func GetEnv(key string, fallback string) string {
	value, ok := os.LookupEnv(key)

	if !ok {
		return fallback
	}

	return value
}