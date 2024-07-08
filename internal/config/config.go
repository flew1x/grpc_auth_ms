package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
)

var cfg *koanf.Koanf

type Config struct {
	GRPCConfig     IGRPCConfig
	JWTConfig      IJWTConfig
	LoggerConfig   ILoggerConfig
	PostgresConfig IPostgresConfig
}

func NewConfig() *Config {
	return &Config{}
}

// InitConfig initializes the global configuration by loading the
// config from the given YAML file and parsing it.
// It panics if there is an error loading or parsing the config.
func (c *Config) InitConfig(configPath, configFile string) {
	cfg = koanf.New(".")

	filePath := filepath.Join(configPath, configFile)

	config := file.Provider(filePath)

	if err := cfg.Load(config, yaml.Parser()); err != nil {
		panic("failed to load config: " + err.Error())
	}

	c.GRPCConfig = NewGRPCConfig()
	c.JWTConfig = NewJWTConfig()
	c.LoggerConfig = NewLoggerConfig()
	c.PostgresConfig = NewPostgresConfig()
}

// MustStringFromEnv returns the value of the environment variable or panics if the environment variable is not set.
//
// Parameters:
// - field: the name of the environment variable to retrieve.
//
// Returns:
// - string: the value of the environment variable.
func mustStringFromEnv(field string) string {
	envValue := os.Getenv(field)

	if envValue == "" {
		panic(fmt.Sprintf("environment variable %s is not set", field))
	}

	return envValue
}

// MustUnmarshal unmarshals the field in the config or panics if the field does not exist.
//
// Parameters:
// - field: the name of the field to retrieve.
// - v: the pointer to the struct to unmarshal into.
//
// Returns:
// - nil
func mustUnmarshalStruct(field string, v any) {
	if err := cfg.Unmarshal(field, v); err != nil {
		panic(err)
	}
}
