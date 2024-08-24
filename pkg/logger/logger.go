package logger

import (
	"log/slog"
	"os"
	"runtime/debug"
	"time"

	"github.com/lmittmann/tint"
)

// LogLevel represents the severity of the log message.
type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
)

// Logger interface defines methods for structured logging.
type Logger interface {
	Info(description string, attributes ...any)
	Debug(description string, attributes ...any)
	Error(description string, err error, attributes ...any)
	Warn(description string, attributes ...any)
	WithOperation(operation string) Logger
	StringAttr(attribute string, value string) any
	AnyAttr(attribute string, value any) any
	With(attributes ...any) Logger
}

// Slogger is an implementation of Logger interface using slog.
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
func InitLogger(mode LogLevel) *Slogger {
	options := &tint.Options{
		Level:      slog.LevelDebug,
		TimeFormat: time.Kitchen,
	}

	var handler slog.Handler

	switch mode {
	case LevelDebug:
		handler = tint.NewHandler(os.Stderr, options)
	case LevelInfo:
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	case LevelWarn:
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn})
	case LevelError:
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})
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

// Debug logs a debug level message.
func (l *Slogger) Debug(description string, attributes ...any) {
	l.logger.Debug(description, attributes...)
}

// Info logs an info level message.
func (l *Slogger) Info(description string, attributes ...any) {
	l.logger.Info(description, attributes...)
}

// Error logs an error level message with the error details.
func (l *Slogger) Error(description string, err error, attributes ...any) {
	if err == nil {
		attrs := append(attributes, slog.String("error", "nil"))

		l.logger.Error(description, attrs...)

		return
	}

	attrs := append(attributes, slog.String("error", err.Error()))
	l.logger.Error(description, attrs...)
}

// Warn logs a warn level message.
func (l *Slogger) Warn(description string, attributes ...any) {
	l.logger.Warn(description, attributes...)
}

// WithOperation returns a new logger with the given operation name.
func (l *Slogger) WithOperation(operation string) Logger {
	newLogger := *l
	newLogger.logger = newLogger.logger.With(slog.String("operation", operation))

	return &newLogger
}

// With returns a new logger with the given attributes.
func (l *Slogger) With(attributes ...any) Logger {
	newLogger := *l
	newLogger.logger = newLogger.logger.With(attributes...)

	return &newLogger
}

// StringAttr returns a string attribute for logging.
func (l *Slogger) StringAttr(attribute string, value string) any {
	return slog.String(attribute, value)
}

// AnyAttr returns an any type attribute for logging.
func (l *Slogger) AnyAttr(attribute string, value any) any {
	return slog.Any(attribute, value)
}
