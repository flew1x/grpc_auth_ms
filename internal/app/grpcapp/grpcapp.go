package grpcapp

import (
	"context"
	"fmt"
	"log/slog"
	grpcauth "msauth/internal/controllers/grpc/v1"
	"msauth/internal/service"
	"net"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type GRPCApp struct {
	Log        *slog.Logger
	GRPCserver *grpc.Server
	Port       int
}

// New creates a new GRPCApp instance with the given logger, service, and port.
// It configures the gRPC server with recovery and logging interceptors.
// The recovery interceptor handles panics by logging and returning an error.
// The logging interceptor logs payload and event info.
// The server is registered with the given service implementation.
// The GRPCApp contains the logger, gRPC server instance, and port.
func New(alog *slog.Logger, service service.Service, port int) *GRPCApp {
	loggingOpts := []logging.Option{
		logging.WithLogOnEvents(
			logging.PayloadReceived, logging.PayloadSent,
		),
	}

	recoveryOpts := []recovery.Option{
		recovery.WithRecoveryHandler(func(p interface{}) (err error) {
			alog.Error("Recovered from panic", slog.Any("panic", p))
			return status.Errorf(codes.Internal, "internal error")
		}),
	}

	gRPCServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			recovery.UnaryServerInterceptor(recoveryOpts...),
			logging.UnaryServerInterceptor(InterceptorLogger(alog), loggingOpts...),
		),
	)

	grpcauth.RegisterServer(gRPCServer, service)

	return &GRPCApp{
		Log:        alog,
		GRPCserver: gRPCServer,
		Port:       port,
	}
}

// InterceptorLogger returns a logging.Logger that forwards log events to the
// provided slog.Logger. This allows integrating slog loggers with gRPC interceptors.
func InterceptorLogger(l *slog.Logger) logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
		l.Log(ctx, slog.Level(lvl), msg, fields...)
	})
}

// Run starts the gRPC server listening on the configured port.
// It returns any error from net.Listen or GRPCserver.Serve.
// The caller should monitor the returned error and handle shutdown.
func (a *GRPCApp) Run() error {
	const operation = "grpcapp.Run"

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", a.Port))
	if err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	a.Log.Info("grpc server started", slog.String("addr", listener.Addr().String()))

	if err := a.GRPCserver.Serve(listener); err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return nil
}

// MustRun starts the gRPC server and panics on any error from Run.
// It should only be used in test code or simple programs where crashing
// on startup failure is preferred over error handling.
func (a *GRPCApp) MustRun() {
	if err := a.Run(); err != nil {
		panic(err)
	}
}

// Stop gracefully stops the gRPC server that was started by Run.
// It logs the stop operation and port before calling GracefulStop on the
// gRPC server.
func (a *GRPCApp) Stop() {
	const operation = "grpcapp.Stop"
	a.Log.With(slog.String("operation", operation)).Info("stopping gRPC server", slog.Int("port", a.Port))
	a.GRPCserver.GracefulStop()
}
