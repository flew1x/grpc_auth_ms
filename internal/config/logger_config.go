package config

const loggingPath = "logging"

type ILoggerConfig interface {
	// GetLoggingMode returns the logging mode
	GetLoggingMode() string
}

type LoggerConfig struct {
	Mode string `koanf:"mode"`
}

func NewLoggerConfig() ILoggerConfig {
	var loggerConfig LoggerConfig

	mustUnmarshalStruct(loggingPath, &loggerConfig)

	return &loggerConfig
}

func (c *LoggerConfig) GetLoggingMode() string {
	return c.Mode
}
