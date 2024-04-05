package main

import (
	"context"
	"errors"
	"log"
	"msauth/internal/app"
	"msauth/internal/config"
	"msauth/pkg/logger"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sync/errgroup"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	gracefulStopError := errors.New("graceful stop signal received")

	loggerConfig := config.NewLoggerConfig()
	logger := logger.InitLogger(loggerConfig.GetLoggingMode())

	grpcConfig := config.NewGRPCConfig()
	application, err := app.New(ctx, logger, grpcConfig)
	if err != nil {
		panic(err)
	}

	var g errgroup.Group
	g.Go(application.GRPCserver.Run)
	g.Go(func() error { return gracefulStop(gracefulStopError) })

	switch g.Wait() {
	case gracefulStopError:
		logger.Info(gracefulStopError.Error())
		application.GRPCserver.Stop()
		logger.Info("gracefully stopped")
	default:
		log.Fatalln(err)
	}
}

func gracefulStop(gracefulStopError error) error {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	<-stop

	return gracefulStopError
}
