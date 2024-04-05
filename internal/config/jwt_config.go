package config

const (
	jwtExpireAccessTokenField = "jwt_expire_access_token"
	jwtExpireRefreshTokenField = "jwt_expire_refresh_token"
)

type IJWTConfig interface {
	GetExpireAccessToken() string
	GetExpireRefreshToken() string
}

type jwtConfig struct{}

func NewJWTConfig() IJWTConfig {
	return &jwtConfig{}
}

func (jwtConfig) GetExpireAccessToken() string {
	return MustString(jwtExpireAccessTokenField)
}

func (jwtConfig) GetExpireRefreshToken() string {
	return MustString(jwtExpireRefreshTokenField)
}
