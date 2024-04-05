package service

import (
	"log/slog"
	"msauth/internal/repository"
	"msauth/internal/service/auth"
)

type Service struct {
	AuthService auth.IAuthService
}

func NewService(logger *slog.Logger, repository *repository.Repository) *Service {
	return &Service{
		AuthService: auth.NewAuthService(logger, repository.IAuthRespository),
	}
}