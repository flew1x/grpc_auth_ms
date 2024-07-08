package config

import (
	"net/url"
	"time"
)

const (
	pgPath             = "postgres"
	pgPasswordFieldEnv = "PGSQL_PASSWORD"
)

type IPostgresConfig interface {
	// GetPostgresHost returns the host for the postgres database.
	GetPostgresHost() string

	// GetPostgresUserInfo returns the user info for the postgres database.
	GetPostgresUserInfo() *url.Userinfo

	// GetPostgresDatabaseName returns the database name for the postgres database.
	GetPostgresDatabaseName() string

	// GetPostgresSSLMode returns the SSL mode for the postgres database.
	GetPostgresSSLMode() string

	// GetPostgresMaxCons returns the maximum number of connections for the postgres database.
	GetPostgresMaxCons() int

	// GetPostgresMaxIdleCons returns the maximum number of idle connections for the postgres database.
	GetPostgresMaxIdleCons() int

	// GetPostgresMaxConLifetime returns the maximum lifetime of a connection for the postgres database.
	GetPostgresMaxConLifetime() time.Duration
}

type PostgresConfig struct {
	Host            string        `koanf:"host"`
	User            string        `koanf:"user"`
	DatabaseName    string        `koanf:"dbname"`
	SSLMode         string        `koanf:"sslmode"`
	MaxConns        int           `koanf:"max_conns"`
	MaxIdleConns    int           `koanf:"max_idle_conns"`
	MaxConnLifetime time.Duration `koanf:"max_conn_lifetime"`
}

func NewPostgresConfig() *PostgresConfig {
	postgresConfig := &PostgresConfig{}
	mustUnmarshalStruct(pgPath, &postgresConfig)

	return postgresConfig
}

func (c *PostgresConfig) GetPostgresHost() string {
	return c.Host
}

func (c *PostgresConfig) GetPostgresUserInfo() *url.Userinfo {
	return url.UserPassword(c.User, mustStringFromEnv(pgPasswordFieldEnv))
}

func (c *PostgresConfig) GetPostgresDatabaseName() string {
	return c.DatabaseName
}

func (c *PostgresConfig) GetPostgresSSLMode() string {
	return c.SSLMode
}

func (c *PostgresConfig) GetPostgresMaxCons() int {
	return c.MaxConns
}

func (c *PostgresConfig) GetPostgresMaxIdleCons() int {
	return c.MaxIdleConns
}

func (c *PostgresConfig) GetPostgresMaxConLifetime() time.Duration {
	return c.MaxConnLifetime
}

func (c *PostgresConfig) GetPostgresPassword() string {
	return mustStringFromEnv(pgPasswordFieldEnv)
}
