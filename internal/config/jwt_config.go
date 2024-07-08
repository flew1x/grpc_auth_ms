package config

import "time"

const (
	jwtPath       = "jwt"
	superJWTField = "SUPER_JWT_SECRET"
	userJWTField  = "USER_JWT_SECRET"
	adminJWTField = "ADMIN_JWT_SECRET"
)

type IJWTConfig interface {
	// GetExpireAccessToken returns the expiration time for access tokens.
	GetExpireAccessToken() time.Duration

	// GetExpireRefreshToken returns the expiration time for refresh tokens.
	GetExpireRefreshToken() time.Duration

	// GetAdminJWTSecretKey returns the admin JWT secret key.
	GetAdminJWTSecretKey() string

	// GetSuperJWTSecretKey returns the super JWT secret key.
	GetSuperJWTSecretKey() string

	// GetUserJWTSecretKey returns the user JWT secret key.
	GetUserJWTSecretKey() string
}

type JWTConfig struct {
	ExpireAccessToken  time.Duration `koanf:"expire_access"`
	ExpireRefreshToken time.Duration `koanf:"expire_refresh"`
}

func NewJWTConfig() *JWTConfig {
	jwtConfig := &JWTConfig{}
	mustUnmarshalStruct(jwtPath, &jwtConfig)

	return jwtConfig
}

func (c *JWTConfig) GetExpireAccessToken() time.Duration {
	return c.ExpireAccessToken
}

func (c *JWTConfig) GetExpireRefreshToken() time.Duration {
	return c.ExpireRefreshToken
}

// GetAdminJWTSecretKey retrieves the admin JWT secret key.
//
// Returns:
// - The admin JWT secret key.
func (*JWTConfig) GetAdminJWTSecretKey() string {
	return mustStringFromEnv(adminJWTField)
}

// GetSuperJWTSecretKey retrieves the super JWT secret key.
//
// Returns:
// - The super JWT secret key.
func (*JWTConfig) GetSuperJWTSecretKey() string {
	return mustStringFromEnv(superJWTField)
}

func (*JWTConfig) GetUserJWTSecretKey() string {
	return mustStringFromEnv(userJWTField)
}
