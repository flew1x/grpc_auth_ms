package logger

import (
	"log/slog"
	"os"
	"runtime/debug"
	"time"

	"github.com/lmittmann/tint"
)

type Logger interface {
	// Info logs an information message.
	Info(description string, attributes ...any)

	// Debug logs a debug message.
	Debug(description string, attributes ...any)

	// Error logs an error message.
	Error(description string, err error, attributes ...any)

	// Warn logs a warning message.
	Warn(description string, attributes ...any)

	// WithOperation adds an operation field to the logger.
	WithOperation(operation string) Logger

	// StringAttr adds a string attribute to the logger.
	StringAttr(attribute string, value string) any

	// AnyAttr adds an any attribute to the logger.
	AnyAttr(attribute string, value any) any
}

type Slogger struct {
	logger *slog.Logger
}

// InitLogger initializes a new logger instance based on the provided
// mode string. It returns a pointer to the initialized slog.Logger.
//
// If mode is "dev", it configures the logger for debug level logging
// to stdout.
//
// If mode is "production", it configures the logger for info level
// logging to stdout.
func InitLogger(mode string) *Slogger {
	options := &tint.Options{
		Level:      slog.LevelDebug,
		TimeFormat: time.Kitchen,
	}

	var handler slog.Handler

	switch {
	case mode == "dev":
		handler = tint.NewHandler(os.Stderr, options)
	case mode == "prod":
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	default:
		handler = tint.NewHandler(os.Stderr, options)
	}

	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		buildInfo = &debug.BuildInfo{GoVersion: "unknown"}
	}

	logger := slog.New(handler).With(
		slog.Group("program_info",
			slog.String("go_version", buildInfo.GoVersion),
		),
	)

	return &Slogger{
		logger: logger,
	}
}

func (l *Slogger) Debug(description string, attributes ...any) {
	l.logger.Debug(description, attributes...)
}

func (l *Slogger) Info(description string, attributes ...any) {
	l.logger.Info(description, attributes...)
}

func (l *Slogger) Error(description string, err error, attributes ...any) {
	attrs := append(attributes, slog.String("error", err.Error()))
	l.logger.Error(description, attrs...)
}

func (l *Slogger) Warn(description string, attributes ...any) {
	l.logger.Warn(description, attributes...)
}

func (l *Slogger) WithOperation(operation string) Logger {
	newLogger := *l
	newLogger.logger = newLogger.logger.With(slog.String("operation", operation))

	return &newLogger
}

func (l *Slogger) StringAttr(attribute string, value string) any {
	return slog.String(attribute, value)
}

func (l *Slogger) AnyAttr(attribute string, value any) any {
	return slog.Any(attribute, value)
}
