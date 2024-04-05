package suite

import (
	"context"

	"msauth/internal/api/grpc_api"
	"msauth/internal/config"
	"net"
	"strconv"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Suite struct {
	*testing.T
	JWTConfig  config.IJWTConfig
	AuthClient grpc_api.AuthClient
}

// New creates a new Suite for testing. It initializes a gRPC client, context,
// and auth client to be used in tests. The context is canceled on cleanup.
func New(t *testing.T) (context.Context, *Suite) {
	t.Helper()
	t.Parallel()

	cfg := config.NewGRPCConfig()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.GetTimeout()*int(time.Millisecond)))
	t.Cleanup(func() {
		t.Helper()
		cancel()
	})

	grpcAddress := net.JoinHostPort("", strconv.Itoa(cfg.GetPort()))

	client, err := grpc.DialContext(context.Background(), grpcAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc server connection failed: %v", err)
	}
	authClient := grpc_api.NewAuthClient(client)

	suite := new(Suite)
	suite.T = t
	suite.AuthClient = authClient
	return ctx, suite
}
