package main

import (
	"errors"
	"msauth/internal/app"
	"msauth/internal/config"
	"msauth/pkg/logger"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sync/errgroup"
)

var (
	ErrGracefulStop = errors.New("graceful stop signal received")
)

func main() {
	cfg := config.NewConfig()
	cfg.InitConfig(os.Getenv("CONFIG_PATH"), os.Getenv("CONFIG_FILE"))

	newLogger := logger.InitLogger(cfg.LoggerConfig.GetLoggingMode())

	application, err := app.New(newLogger, cfg)
	if err != nil {
		newLogger.Error("failed to create application", err)

		return
	}

	var errorGroup errgroup.Group

	errorGroup.Go(func() error {
		return application.GRPCServer.Run()
	})

	errorGroup.Go(func() error {
		return gracefulStop(ErrGracefulStop)
	})

	switch err = errorGroup.Wait(); {
	case errors.Is(errorGroup.Wait(), ErrGracefulStop):
		newLogger.Info(ErrGracefulStop.Error())

		application.GRPCServer.Stop()

		newLogger.Info("gracefully stopped")
	default:
		newLogger.Error("failed to start the application", err)
	}
}

func gracefulStop(gracefulStopError error) error {
	stop := make(chan os.Signal, 1)

	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	<-stop

	return gracefulStopError
}
