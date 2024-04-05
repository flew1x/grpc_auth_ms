package app

import (
	"context"
	"log/slog"
	"msauth/internal/app/grpcapp"
	"msauth/internal/config"
	"msauth/internal/database"
	"msauth/internal/repository"
	"msauth/internal/service"
)

type App struct {
	GRPCserver *grpcapp.GRPCApp
	Port       int
}

// New creates a new App instance. It initializes the database, repository, and
// service once, and then uses them to create the GRPC server. The GRPC server
// listens on the provided port. The App struct contains the initialized GRPC
// server and port.
func New(ctx context.Context, logger *slog.Logger, grpcConfig config.IGRPCConfig) (*App, error) {
	db := database.Open()
	repo := repository.NewRepository(db)
	svc := service.NewService(logger, repo)

	return &App{
		GRPCserver: grpcapp.New(logger, *svc, grpcConfig.GetPort()),
		Port:       grpcConfig.GetPort(),
	}, nil
}
