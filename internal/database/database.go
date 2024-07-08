package database

import (
	"context"
	"database/sql"
	"fmt"
	"msauth/internal/config"
	"msauth/internal/entity"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/uptrace/bun/extra/bundebug"
)

type Client struct {
	DB *bun.DB
}

// InitDatabase initializes the database with the given configuration.
//
// It creates a new context with a timeout of one minute. It then creates a slice
// of tables to be created in the database. Each table is a new instance of an
// entity struct.
//
// It opens a new database connection using the Open function with the given
// configuration. It then iterates over each table and creates a new table in the
// database using the NewCreateTable method of the database instance. If the table
// already exists, it is not created again.
//
// Finally, it returns a new Client instance with the created database
// instance.
//
// Parameters:
// - config: an interface that implements the IPostgresConfig interface,
// representing the configuration for the database connection.
//
// Returns:
// - Client: a struct that contains the database instance.
func InitDatabase(config config.IPostgresConfig) Client {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tables := []any{
		new(entity.User),
	}

	initedDatabase := Open(config)

	for _, v := range tables {
		if _, err := initedDatabase.NewCreateTable().Model(v).IfNotExists().Exec(ctx); err != nil {
			panic(ErrFailedToInitDB)
		}
	}

	return Client{DB: initedDatabase}
}

// Open creates a new database connection based on the provided configuration.
//
// It constructs the data source name (DSN) using the provided configuration,
// opens a new database connection, and sets the maximum number of open
// connections and the maximum lifetime of a connection.
//
// It also sets up a Bun database instance with the created connection and a new
// instance of the PostgreSQL dialect.
//
// Finally, it adds a query hook to the database instance to log all queries.
//
// Parameters:
//   - cfg: an interface that implements the IPostgresConfig interface,
//     representing the configuration for the database connection.
//
// Returns:
//   - *bun.DB: a pointer to a Bun database instance that can be used to
//     perform database operations.
func Open(cfg config.IPostgresConfig) *bun.DB {
	dsn := fmt.Sprintf(
		AddressTemplate,
		cfg.GetPostgresUserInfo(),
		cfg.GetPostgresHost(),
		cfg.GetPostgresDatabaseName(),
		cfg.GetPostgresSSLMode(),
	)

	pgdb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
	pgdb.SetMaxOpenConns(cfg.GetPostgresMaxCons())
	pgdb.SetMaxIdleConns(cfg.GetPostgresMaxIdleCons())
	pgdb.SetConnMaxLifetime(cfg.GetPostgresMaxConLifetime())

	db := bun.NewDB(pgdb, pgdialect.New())
	db.AddQueryHook(bundebug.NewQueryHook(bundebug.WithVerbose(true)))

	return db
}
