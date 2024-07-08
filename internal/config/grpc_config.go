package config

const (
	grpcPath = "grpc"
)

// IGRPCConfig is the interface for GRPCConfig.
//
// It provides methods to get the necessary configuration values for the gRPC server.
type IGRPCConfig interface {
	// GetGRPCPort returns the gRPC port number.
	GetGRPCPort() int

	// GetGRPCTimeout returns the gRPC timeout value.
	GetGRPCTimeout() int
}

type GRPCConfig struct {
	GRPCPort    int `koanf:"port"`
	GRPCTimeout int `koanf:"timeout"`
}

func NewGRPCConfig() *GRPCConfig {
	grpcConfig := &GRPCConfig{}
	mustUnmarshalStruct(grpcPath, &grpcConfig)

	return grpcConfig
}

func (c *GRPCConfig) GetGRPCPort() int {
	return c.GRPCPort
}

func (c *GRPCConfig) GetGRPCTimeout() int {
	return c.GRPCTimeout
}
