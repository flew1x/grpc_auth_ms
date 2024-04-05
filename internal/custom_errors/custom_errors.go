package custom_errors

import "errors"

var (
	ErrUserExists   = errors.New("user already exists")
	ErrUserNotFound = errors.New("user not found")

	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrInvalidRefreshTokenExpired = errors.New("refresh token expired")
	ErrInvalidRefreshTokenMalformed = errors.New("invalid refresh token malformed")

	ErrInvalidAccessToken = errors.New("invalid access token")
	ErrInvalidAccessTokenExpired = errors.New("access token expired")
	ErrInvalidAccessTokenMalformed = errors.New("invalid access token malformed")
)
