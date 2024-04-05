package config

import (
	"net/url"
)

const (
	pgHostField         = "pgsql_host"
	pgUserField         = "pgsql_user"
	pgPasswordField     = "pgsql_password"
	pgDatabaseNameField = "pgsql_dbname"
	pgSSLModeField      = "pgsql_sslmode"
	maxConns            = "pgsql_max_conns"
	maxIdleConns        = "pgsql_max_idle_conns"
	maxConnsLifetime    = "pgsql_max_conn_lifetime"
)

type IPostgresConfig interface {
	GetHost() string
	GetUserInfo() *url.Userinfo
	GetDatabaseName() string
	GetSSLMode() string
	GetMaxConns() int
	GetMaxIdleConns() int
	GetMaxConnLifetime() string
}

type postgresConfig struct{}

func NewPostgresConfig() IPostgresConfig {
	return &postgresConfig{}
}

func (postgresConfig) GetHost() string {
	return MustString(pgHostField)
}

func (postgresConfig) GetUserInfo() *url.Userinfo {
	userInfo := url.UserPassword(
		MustString(pgUserField),
		MustString(pgPasswordField),
	)
	return userInfo
}

func (postgresConfig) GetDatabaseName() string {
	return MustString(pgDatabaseNameField)
}

func (postgresConfig) GetSSLMode() string {
	return MustString(pgSSLModeField)
}

func (postgresConfig) GetMaxConns() int {
	return MustInt(maxConns)
}

func (postgresConfig) GetMaxIdleConns() int {
	return MustInt(maxIdleConns)
}

func (postgresConfig) GetMaxConnLifetime() string {
	return MustString(maxConnsLifetime)
}