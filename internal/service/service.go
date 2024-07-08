package service

import (
	"msauth/internal/config"
	"msauth/internal/repository"
	"msauth/internal/service/auth"
	"msauth/pkg/logger"
)

type Service struct {
	AuthService auth.IAuthService
}

func NewService(logger logger.Logger, repository *repository.Repository, config *config.Config) *Service {
	return &Service{
		AuthService: auth.NewAuthService(logger, repository.IAuthRepository, config),
	}
}
