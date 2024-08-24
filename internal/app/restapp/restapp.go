package restapp

import (
	"context"
	"errors"
	"fmt"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"msauth/internal/config"
	"msauth/pkg/logger"
	"msauth/pkg/proto/auth"
	"net/http"
)

type RestApp struct {
	Logger logger.Logger
	Host   string
	Config config.IGRPCConfig
}

func New(logger logger.Logger, host string, config config.IGRPCConfig) *RestApp {
	return &RestApp{
		Logger: logger,
		Host:   host,
		Config: config,
	}
}

func (a *RestApp) RunREST(ctx context.Context) error {
	gwMux := runtime.NewServeMux()

	options := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}

	authHost := fmt.Sprintf("localhost:%d", a.Config.GetGRPCPort())

	if err := auth.RegisterAuthHandlerFromEndpoint(ctx, gwMux, authHost, options); err != nil {
		return errors.New("failed to register auth handler from endpoint: " + err.Error())
	}

	a.Logger.Info("RESTful auth host started", a.Logger.AnyAttr("host", a.Host))

	if err := http.ListenAndServe(a.Host, gwMux); err != nil {
		return errors.New("failed to listen and serve: " + err.Error())
	}

	return nil
}
