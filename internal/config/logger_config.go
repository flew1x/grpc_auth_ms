package config

const loggingModeField = "logging_mode"

type ILoggerConfig interface {
	GetLoggingMode() string
}

type loggerConfig struct{}

func NewLoggerConfig() ILoggerConfig {
	return &loggerConfig{}
}

func (loggerConfig) GetLoggingMode() string {
	return MustString(loggingModeField)
}
