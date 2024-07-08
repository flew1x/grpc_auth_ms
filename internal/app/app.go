package app

import (
	"msauth/internal/app/grpcapp"
	"msauth/internal/config"
	"msauth/internal/database"
	"msauth/internal/repository"
	"msauth/internal/service"
	"msauth/pkg/logger"
)

type App struct {
	GRPCServer *grpcapp.App
}

// New creates a new App instance. It initializes the database, repositories,
// services and GRPC server. The GRPC server listens on the provided port.
// The App struct contains the initialized GRPC server and port.
func New(logger logger.Logger, cfg *config.Config) (*App, error) {
	initialedDatabase := database.InitDatabase(cfg.PostgresConfig)

	newRepository := repository.NewRepository(
		logger,
		initialedDatabase.DB,
	)

	newService := service.NewService(logger, newRepository, cfg)

	grpcApp := grpcapp.New(logger, newService, cfg)

	return &App{GRPCServer: grpcApp}, nil
}
