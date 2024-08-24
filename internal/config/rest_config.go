package config

const (
	restPath = "rest"
)

// IRESTConfig is the interface for RESTConfig.
type IRESTConfig interface {
	GetRestPort() int

	GetRestHost() string
}

type RESTConfig struct {
	RESTPort int    `koanf:"port"`
	RESTHost string `koanf:"host"`
}

func NewRESTConfig() *RESTConfig {
	restConfig := &RESTConfig{}
	mustUnmarshalStruct(restPath, &restConfig)

	return restConfig
}

func (c *RESTConfig) GetRestPort() int {
	return c.RESTPort
}

func (c *RESTConfig) GetRestHost() string {
	return c.RESTHost
}
