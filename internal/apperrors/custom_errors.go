package apperrors

import "errors"

var (
	ErrUserExists   = errors.New("user already exists")
	ErrUserNotFound = errors.New("user not found")

	ErrInvalidCredentials           = errors.New("invalid credentials")
	ErrInvalidRefreshToken          = errors.New("invalid refresh token")
	ErrInvalidRefreshTokenExpired   = errors.New("refresh token expired")
	ErrInvalidRefreshTokenMalformed = errors.New("invalid refresh token malformed")

	ErrInvalidAccessToken          = errors.New("invalid access token")
	ErrInvalidAccessTokenExpired   = errors.New("access token expired")
	ErrInvalidAccessTokenMalformed = errors.New("invalid access token malformed")

	ErrPermissionDenied      = errors.New("permission denied")
	ErrCannotChangeAdminRole = errors.New("cannot change admin role")

	ErrTooManyAttempts           = errors.New("too many attempts try later")
	ErrWaitingTimeForAnotherCode = errors.New("waiting time for another code")

	ErrInvalidUserRole = errors.New("invalid user role")
)
