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

// init initializes the database by creating tables if they don't exist.
// This function should be called once on application start.
func init() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tables := []any{
		new(entity.User),
	}

	db := Open()
	for _, v := range tables {
		if _, err := db.NewCreateTable().Model(v).IfNotExists().Exec(ctx); err != nil {
			panic(fmt.Errorf("cannot init database: %v", err))
		}
	}
}


// Open returns a database connection to the PostgreSQL database.
// This function should be called once on application start.
func Open() *bun.DB {
	cfg := config.NewPostgresConfig()
	dsn := fmt.Sprintf(
		"postgres://%s@%s/%s?sslmode=%s",
		cfg.GetUserInfo(),
		cfg.GetHost(),
		cfg.GetDatabaseName(),
		cfg.GetSSLMode(),
	)

	pgdb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))

	pgdb.SetMaxOpenConns(cfg.GetMaxConns())
	pgdb.SetMaxIdleConns(cfg.GetMaxIdleConns())

	duration, err := time.ParseDuration(cfg.GetMaxConnLifetime())
	if err != nil {
		panic(err)
	}
	pgdb.SetConnMaxLifetime(duration)

	db := bun.NewDB(pgdb, pgdialect.New())
	db.AddQueryHook(bundebug.NewQueryHook(bundebug.WithVerbose(true)))

	return db
}
