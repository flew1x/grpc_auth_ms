package repository

import (
	"log/slog"
	authRepo "msauth/internal/repository/auth"

	"github.com/uptrace/bun"
)

type Repository struct {
	logger           *slog.Logger
	IAuthRespository authRepo.IAuthRespository
}

// NewRepository returns a new Repository instance with dependencies initialized.
func NewRepository(db *bun.DB) *Repository {
	return &Repository{
		logger:           slog.Default(),
		IAuthRespository: authRepo.NewAuthRespository(db),
	}
}
