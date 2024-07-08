package repository

import (
	authRepo "msauth/internal/repository/auth"
	"msauth/pkg/logger"

	"github.com/uptrace/bun"
)

type Repository struct {
	IAuthRepository authRepo.IAuthRepository
}

// NewRepository returns a new Repository instance with dependencies initialized.
func NewRepository(logger logger.Logger, db *bun.DB) *Repository {
	return &Repository{
		IAuthRepository: authRepo.NewRepository(logger, db),
	}
}
