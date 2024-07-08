package grpcapp

import (
	"context"
	"fmt"
	"log/slog"
	"msauth/internal/config"
	grpcauth "msauth/internal/controllers/grpc/v1"
	"msauth/internal/service"
	"msauth/pkg/logger"
	"net"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type App struct {
	Logger     logger.Logger
	GRPCServer *grpc.Server
	Config     *config.Config
}

func New(logger logger.Logger, service *service.Service, config *config.Config) *App {
	loggingOpts := []logging.Option{
		logging.WithLogOnEvents(logging.PayloadReceived, logging.PayloadSent),
	}

	recoveryOpts := []recovery.Option{
		recovery.WithRecoveryHandler(func(p any) (err error) {
			logger.Error("recovered from panic", fmt.Errorf("%v", p))

			return status.Errorf(codes.Internal, "internal server error")
		}),
	}

	gRPCServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			recovery.UnaryServerInterceptor(recoveryOpts...),
			logging.UnaryServerInterceptor(InterceptorLogger(logger), loggingOpts...),
		),
	)

	grpcauth.RegisterServer(gRPCServer, service)

	return &App{
		Logger:     logger,
		GRPCServer: gRPCServer,
		Config:     config,
	}
}

func InterceptorLogger(logger logger.Logger) logging.Logger {
	return logging.LoggerFunc(func(_ context.Context, _ logging.Level, msg string, fields ...any) {
		logger.Debug(msg, fields...)
	})
}

func (a *App) Run() error {
	const op = "app.grpcapp.Run"

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", a.Config.GRPCConfig.GetGRPCPort()))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	a.Logger.Info("gRPC server started", slog.String("addr", listener.Addr().String()))

	if err := a.GRPCServer.Serve(listener); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (a *App) Stop() {
	const op = "app.grpcapp.Stop"
	logger := a.Logger.WithOperation(op)

	logger.Info("stopping gRPC server", slog.Int("addr", a.Config.GRPCConfig.GetGRPCPort()))

	a.GRPCServer.GracefulStop()
}
