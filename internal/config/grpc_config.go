package config

const (
	grpcPortField    = "grpc_port"
	grpcTimeoutField = "grpc_timeout"

	userdataServiceHostField = "grpc_userdata_service_host"
)

type IGRPCConfig interface {
	GetPort() int
	GetTimeout() int
	GetUserdataServiceHost() string
}

type grpcConfig struct{}

func NewGRPCConfig() IGRPCConfig {
	return &grpcConfig{}
}

func (*grpcConfig) GetPort() int {
	return MustInt(grpcPortField)
}

func (*grpcConfig) GetTimeout() int {
	return MustInt(grpcPortField)
}

func (*grpcConfig) GetUserdataServiceHost() string {
	return MustString(userdataServiceHostField)
}
