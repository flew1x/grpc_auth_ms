package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"msauth/internal/config"
	"msauth/internal/custom_errors"
	"msauth/internal/entity"
	authRepo "msauth/internal/repository/auth"
	"msauth/pkg/logger"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type IAuthService interface {
	Register(ctx context.Context, user *entity.User) (entity.AuthResponse, error)
	Login(ctx context.Context, user *entity.User) (entity.AuthResponse, error)
	Refresh(ctx context.Context, refToken string, role entity.UserRole) (accessToken, refreshToken string, err error)
	CheckJWT(ctx context.Context, accessToken string, role entity.UserRole) (valid bool, userID uuid.UUID, err error)
}

type authService struct {
	logger     *slog.Logger
	repository authRepo.IAuthRespository
	config     config.IJWTConfig
}

func NewAuthService(logger *slog.Logger, authRepo authRepo.IAuthRespository) IAuthService {
	return &authService{
		logger:     logger,
		repository: authRepo,
		config:     config.NewJWTConfig(),
	}
}


// GetJWTSecretKey retrieves the JWT secret key from the environment variable
// {role}_JWT_SECRET. If the environment variable is not set, it tries to load
// the key from the .env file. If the key is still not found, it returns an error.
//
// The function first checks if the environment variable is set. If it is, it
// returns the value of the environment variable.
//
// If the environment variable is not set, the function tries to load the key
// from the .env file. If the key is found in the .env file, it returns the key.
// If the key is not found in the .env file, it returns an error.
//
// This function is used to retrieve the secret key for generating JWT tokens
// for users with different roles. The secret key is not stored in the database
// to prevent unauthorized access to the secret key.
func (a *authService) GetJWTSecretKey(role entity.UserRole) (string, error) {
	secretKey := os.Getenv(string(role) + "_JWT_SECRET")
	if len(secretKey) != 0 {
		return secretKey, nil
	}

	err := godotenv.Load(".env")
	if err != nil {
		return "", err
	}

	secretKey = os.Getenv(string(role) + "_JWT_SECRET")
	if len(secretKey) == 0 {
		return "", fmt.Errorf("%s_JWT_SECRET env variable is not set", role)
	}
	return secretKey, nil
}

// Register registers a new user in the database. It generates a password hash from the
// provided plaintext password, creates a user entity, and stores it in the database.
// It generates and returns two tokens: refreshToken and accessToken.
//
// The refreshToken is used to authenticate the user on subsequent requests.
// The accessToken is a JWT token that contains the user's ID, email.
//
// It returns an error if the input entity is nil, or if something goes wrong during
// the registration process.
func (a *authService) Register(ctx context.Context, user *entity.User) (entity.AuthResponse, error) {
	const operation = "Auth.Register"

	if user == nil {
		return entity.AuthResponse{}, custom_errors.ErrInvalidCredentials
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		a.logger.Error("failed to generate password hash", logger.Err(err))
		return entity.AuthResponse{}, fmt.Errorf("%s: %w", operation, err)
	}

	user.Password = string(hashedPassword)
	user.Role = entity.USER_ROLE

	userFromDB, err := a.repository.Register(ctx, user)
	if err != nil {
		return entity.AuthResponse{}, fmt.Errorf("%s: %w", operation, err)
	}

	refreshToken, accessToken, err := a.GenTokens(userFromDB, operation)
	if err != nil {
		return entity.AuthResponse{}, err
	}

	return entity.AuthResponse{RefreshToken: refreshToken, AccessToken: accessToken, Role: userFromDB.Role}, nil
}

// Login authenticates a user by email/phone and password. It retrieves the user from
// the repository, compares the password hash, and returns the user's tokens if valid.
//
// It returns the refresh token, access token, and the user's role.
//
// The refresh token is used to authenticate the user on subsequent requests.
// The access token is a JWT token that contains the user's ID, email, and phone number.
// The role is the user's role in the system.
//
// It returns an error if something goes wrong during the login process.
// If the user credentials are invalid, it returns ErrInvalidCredentials.
func (a *authService) Login(ctx context.Context, user *entity.User) (entity.AuthResponse, error) {
	const operation = "Auth.Login"

	if user == nil {
		return entity.AuthResponse{}, fmt.Errorf("%s: %w", operation, custom_errors.ErrInvalidCredentials)
	}

	userFromDB, err := a.repository.Login(ctx, user)
	if err != nil {
		a.logger.Error("failed to login", logger.Err(err))
		return entity.AuthResponse{}, fmt.Errorf("%s: %w", operation, err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(userFromDB.Password), []byte(user.Password)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			a.logger.Error("invalid credentials", logger.Err(err))
			return entity.AuthResponse{}, fmt.Errorf("%s: %w", operation, custom_errors.ErrInvalidCredentials)
		}

		a.logger.Error("failed to login", logger.Err(err))
		return entity.AuthResponse{}, fmt.Errorf("%s: %w", operation, err)
	}

	refreshToken, accessToken, err := a.GenTokens(userFromDB, operation)
	if err != nil {
		return entity.AuthResponse{}, err
	}

	return entity.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Role:         userFromDB.Role,
	}, nil
}


// VerifyRefreshToken verifies the refresh token.
//
// It takes the refresh token, role, and returns the JWT claims if the token is valid.
//
// The refresh token is a JWT token that contains the user's ID, email.
// The role is the user's role in the system.
//
// It returns an error if the token is invalid.
// If the token is malformed, it returns ErrInvalidRefreshTokenMalformed.
// If the token is expired, it returns ErrInvalidRefreshTokenExpired.
// If the token is not valid, it returns ErrInvalidRefreshToken.
func (a *authService) VerifyRefreshToken(refToken string, role entity.UserRole) (jwt.MapClaims, error) {
	const operation = "Auth.Refresh"

	secretKey, err := a.GetJWTSecretKey(role)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", operation, err)
	}

	token, err := jwt.Parse(refToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return nil, fmt.Errorf("%s: %w", operation, custom_errors.ErrInvalidRefreshTokenMalformed)
			} else if ve.Errors&jwt.ValidationErrorExpired != 0 {
				return nil, fmt.Errorf("%s: %w", operation, custom_errors.ErrInvalidRefreshTokenExpired)
			}
		}
		return nil, fmt.Errorf("%s: %w", operation, custom_errors.ErrInvalidRefreshToken)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("%s: %w", operation, custom_errors.ErrInvalidRefreshToken)
	}

	return claims, nil
}


// getUserFromRefreshToken retrieves the user from the refresh token claims
//
// It takes the JWT claims from the refresh token, the operation, and a context.
//
// It returns the user that the refresh token belongs to, and a nil error if the user exists.
// If the user does not exist, it returns a ErrInvalidRefreshToken error.
// If there is an error from the repository, it returns a wrapped error.
func (a *authService) getUserFromRefreshToken(ctx context.Context, claims jwt.MapClaims, operation string) (*entity.User, error) {
	id, ok := claims["id"]
	if !ok {
		return nil, fmt.Errorf("%s: %w", operation, custom_errors.ErrInvalidRefreshToken)
	}

	parsedID, err := uuid.Parse(id.(string))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", operation, err)
	}

	user, err := a.repository.GetUserByID(ctx, parsedID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", operation, err)
	}

	return user, nil
}


// Refresh generates new access and refresh tokens for the user that the refresh
// token belongs to.
//
// It takes the refresh token, the user's role, and a context.
//
// It verifies the refresh token, retrieves the user from the database, generates
// new tokens, and returns the new access and refresh tokens.
//
// If the refresh token is invalid, it returns an error.
// If there is an error from the repository, it returns a wrapped error.
//
// If everything goes well, it returns the new access and refresh tokens.
func (a *authService) Refresh(ctx context.Context, refToken string, role entity.UserRole) (accessToken, refreshToken string, err error) {
	const operation = "Auth.Refresh"

	claims, err := a.VerifyRefreshToken(refToken, role)
	if err != nil {
		return "", "", err
	}

	user, err := a.getUserFromRefreshToken(ctx, claims, operation)
	if err != nil {
		return "", "", err
	}

	refToken, accessToken, err = a.GenTokens(user, operation)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", operation, err)
	}

	return accessToken, refToken, nil
}

// CheckJWT validates the access token by decoding it and checking if it's a valid
// access token issued by this service. If it's valid, it returns the user ID of the
// user that the token belongs to.
//
// If the access token is invalid or something goes wrong, it returns an error.
//
// If the access token is invalid, it returns one of the following errors:
//   - ErrInvalidAccessTokenMalformed
//   - ErrInvalidAccessTokenExpired
//   - ErrInvalidAccessToken
//
// If everything goes well, it returns true and the user ID, and a nil error.
func (a *authService) CheckJWT(ctx context.Context, accessToken string, role entity.UserRole) (valid bool, userID uuid.UUID, err error) {
	const operation = "Auth.CheckJWT"

	secretKey, err := a.GetJWTSecretKey(role)
	if err != nil {
		return false, uuid.Nil, fmt.Errorf("%s: %w", operation, err)
	}

	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&(jwt.ValidationErrorMalformed|jwt.ValidationErrorSignatureInvalid) != 0 {
				return false, uuid.Nil, fmt.Errorf("%s: %w", operation, custom_errors.ErrInvalidAccessToken)
			}
			if ve.Errors&jwt.ValidationErrorExpired != 0 {
				return false, uuid.Nil, fmt.Errorf("%s: %w", operation, custom_errors.ErrInvalidAccessTokenExpired)
			}
		}
		return false, uuid.Nil, fmt.Errorf("%s: %w", operation, custom_errors.ErrInvalidAccessTokenMalformed)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return false, uuid.Nil, fmt.Errorf("%s: %w", operation, custom_errors.ErrInvalidAccessToken)
	}

	idStr, ok := claims["id"].(string)
	if !ok {
		return false, uuid.Nil, fmt.Errorf("%s: %w", operation, custom_errors.ErrInvalidAccessToken)
	}

	userID, err = uuid.Parse(idStr)
	if err != nil {
		return false, uuid.Nil, fmt.Errorf("%s: %w", operation, custom_errors.ErrInvalidAccessToken)
	}

	return true, userID, nil
}


// GenTokens generates new refresh and access tokens for the given user.
//
// It generates a new refresh token with the user's id and a flag indicating that it's a
// refresh token as claims. It signs the token using the secret key from the JWT
// configuration and sets the expiration time to 2 weeks.
//
// It also generates a new access token with the user's id, email, and phone number as
// claims. It sets the expiration time to 1 day.
//
// If something goes wrong, it returns an error.
//
// If everything goes well, it returns the new refresh and access tokens.
func (a *authService) GenTokens(user *entity.User, operation string) (refreshToken, accessToken string, err error) {
	refToken, err := a.GenRefreshToken(user)
	if err != nil {
		a.logger.Error("failed to generate refresh token", logger.Err(err))
		return "", "", fmt.Errorf("%s: %w", operation, err)
	}

	accToken, err := a.GenAccessToken(user.ID, user.Role)
	if err != nil {
		a.logger.Error("failed to generate access token", logger.Err(err))
		return "", "", fmt.Errorf("%s: %w", operation, err)
	}

	return refToken, accToken, nil
}


// GenRefreshToken generates a new refresh token for the given user.
//
// It generates a new refresh token with the user's id and a flag indicating that it's a
// refresh token as claims. It signs the token using the secret key from the JWT
// configuration and sets the expiration time to 2 weeks.
//
// The generated token is returned as a string. If there is an error, it is returned
// as a second value.
func (a *authService) GenRefreshToken(user *entity.User) (string, error) {
	duration, err := time.ParseDuration(a.config.GetExpireRefreshToken())
	if err != nil {
		return "", fmt.Errorf("failed to parse expire refresh token duration: %w", err)
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.MapClaims{
			"id":         user.ID,
			"is_refresh": true,
			"exp":        time.Now().Add(duration).Unix(),
		},
	)

	secretKey, err := a.GetJWTSecretKey(user.Role)
	if err != nil {
		return "", err
	}

	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}



// GenAccessToken generates a new access token for the user with the given ID and role.
//
// It generates a new access token with the user's ID as a claim and sets the expiration
// time to the value returned by the GetExpireAccessToken method of the JWT configuration.
//
// If something goes wrong, it returns an error.
//
// If everything goes well, it returns the new access token.
func (a *authService) GenAccessToken(id uuid.UUID, role entity.UserRole) (string, error) {
	duration, err := time.ParseDuration(a.config.GetExpireAccessToken())
	if err != nil {
		return "", err
	}

	secretKey, err := a.GetJWTSecretKey(role)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  id,
		"exp": time.Now().Add(duration).Unix(),
	})

	return token.SignedString([]byte(secretKey))
}
