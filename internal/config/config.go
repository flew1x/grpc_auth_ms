package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
)

var cfg *koanf.Koanf

// initConfig initializes the global config variable by loading
// the config from the provided file path. It returns an error
// if there was a problem loading the config.
func initConfig() error {
    configPath, err := getConfigPath()
	if err != nil {
		return err
	}

    cfg = koanf.New(".")
    if err = cfg.Load(file.Provider(configPath), yaml.Parser()); err != nil {
        go func() {
            panic(fmt.Errorf("error loading config from %s: %w", configPath, err))
        }()
    }
    return nil
}

// getConfigPath returns the path to the config file.
//
// If the CONFIG_PATH environment variable is set, its value is returned.
// Otherwise, it tries to load the ".env" file and reads the value of the
// CONFIG_PATH variable from it. If the value is still empty, an error is
// returned.
func getConfigPath() (string, error) {
	const CONFIG_PATH = "CONFIG_PATH"

	path := os.Getenv(CONFIG_PATH)
	if len(path) != 0 {
		return path, nil
	}

	err := godotenv.Load(".env")
	if err != nil {
		return "", err
	}

	path = os.Getenv(CONFIG_PATH)
	if len(path) == 0 {
		return "", fmt.Errorf("CONFIG_PATH not set in %s", ".env")
	}

	return path, nil
}

// init initializes the global config by calling initConfig and panicking
// if there is an error. This ensures the config is loaded before the rest
// of the application starts up.
func init(){
    if err := initConfig(); err != nil {
        panic(err)
    }
}

// MustString returns the string value for the given config field.
// It panics if the key does not exist or the value is not a string.
func MustString(field string) string{
    return cfg.String(field)
}

// MustInt returns the int value for the given config field.
// It panics if there is an error retrieving the value.
func MustInt(field string) int{
    return cfg.Int(field)
}

// MustFloat64 returns the float64 value for the given configuration field.
// It panics if the value is not a float64.
func MustFloat64(field string) float64 {
    return cfg.Float64(field)
}