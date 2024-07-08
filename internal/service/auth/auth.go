package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"log/slog"
	"msauth/internal/apperrors"
	"msauth/internal/config"
	"msauth/internal/entity"
	"msauth/internal/repository/auth"
	"msauth/pkg/logger"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type IAuth interface {
	// Register registers a new user account.
	// It checks if a user with the same email already exists.
	// If no existing user is found, it inserts the new user into the database.
	// Possible errors:
	// - ErrUserExists if a user with the same email was found.
	// - Database errors from insert operation.
	Register(ctx context.Context, user *entity.User) (entity.IAuthResponse, error)

	// Login authenticates a user by email and password.
	// It returns the authenticated user if found, nil if not found, or an error.
	// It first queries the db to find a user matching the email.
	// If no matching user is found, it returns ErrUserNotFound.
	// If a database error occurs, it is returned.
	// If a user is found, it returns a new copy of the user.
	Login(ctx context.Context, user *entity.User) (entity.IAuthResponse, error)

	// Refresh refreshes the access and refresh tokens.
	// It returns the new access and refresh tokens.
	Refresh(ctx context.Context, refToken string) (accessToken, refreshToken string, err error)

	// CheckJWT checks the JWT token and returns the user ID and role.
	// It returns the user ID and role.
	CheckJWT(ctx context.Context, accessToken string) (id uuid.UUID, userRole entity.Role, err error)
}

// IAuthService is an interface for AuthService
type IAuthService interface {
	// IAuth Authenticate authenticates a user by email and password.
	IAuth

	// GetUserByID retrieves a user by its ID.
	// It returns the user if found, nil if not found, or an error.
	// If no matching user is found, it returns ErrUserNotFound.
	// If a database error occurs, it is returned.
	// If a user is found, it returns the user.
	GetUserByID(ctx context.Context, userID uuid.UUID) (*entity.User, error)

	// GetUserByToken retrieves a user by its JWT access token.
	// It returns the user if found, nil if not found, or an error.
	// If no matching user is found, it returns ErrUserNotFound.
	// If a database error occurs, it is returned.
	// If a user is found, it returns a new copy of the user.
	GetUserByToken(ctx context.Context, accessToken string) (*entity.User, error)

	// GetUserInfoByJWT retrieves user information by its JWT access token.
	// It returns the user information.
	GetUserInfoByJWT(ctx context.Context) (userInfo UserInfo, err error)

	// SearchByEmail retrieves users by email.
	// It returns the users with the given email.
	// If no user was found, it returns an empty slice, not an error.
	// If a database error occurs, it is returned.
	// If users are found, it returns the users.
	SearchByEmail(ctx context.Context, email string) ([]*entity.User, error)

	// GetByRole retrieves all users with the given role.
	// It returns all users with the given role, or an error if the query failed.
	// If no user was found, it returns an empty slice, not an error.
	// If a database error occurs, it is returned.
	// If users are found, it returns the users.
	GetByRole(ctx context.Context, role entity.Role) ([]*entity.User, error)

	// ChangeRole changes the role of a user.
	// It updates the role of the user in the database.
	// If no user was found with the given ID, it returns ErrUserNotFound.
	// If a database error occurs, it is returned.
	ChangeRole(ctx context.Context, userID uuid.UUID, role entity.Role) error

	// IsUserExists checks if a user exists and email.
	// It returns true if a user with the given email exists, false otherwise.
	// If a database error occurs, it is returned.
	IsUserExists(ctx context.Context, email string) (bool, error)
}

type AuthService struct {
	logger     logger.Logger
	repository auth.IAuthRepository
	configJWT  config.IJWTConfig
	configGRPC config.IGRPCConfig
}

func NewAuthService(
	logger logger.Logger,
	authRepo auth.IAuthRepository,
	config *config.Config) *AuthService {
	return &AuthService{
		logger:     logger,
		repository: authRepo,
		configGRPC: config.GRPCConfig,
		configJWT:  config.JWTConfig,
	}
}

// getJWTSecretKey returns the secret key used to sign JWT tokens for the given user role.
//
// The secret key is read from the environment variables. The env variable names are in the
// format of <role>_JWT_SECRET, e.g. ADMIN_JWT_SECRET, USER_JWT_SECRET.
//
// If the env variable is not set, it tries to load the env variables from a file named .env
// in the project root directory. If the env variable is still not set, it returns an error.
//
// The function is used to create both the refresh token and the access token.
//
// Note that the secret key should be kept private and secure.
func (a *AuthService) getJWTSecretKey(role entity.Role) (string, error) {
	const op = "getJWTSecretKey"
	operation := a.logger.WithOperation(op)

	switch role {
	case entity.AdminRole:
		operation.Debug("getting admin secret key")

		return a.configJWT.GetAdminJWTSecretKey(), nil

	case entity.UserRole:
		operation.Debug("getting user secret key")

		return a.configJWT.GetUserJWTSecretKey(), nil

	case entity.SuperRole:
		operation.Debug("getting super secret key")

		return a.configJWT.GetSuperJWTSecretKey(), nil
	}

	return "", apperrors.ErrInvalidUserRole
}

type UserInfo struct {
	UserID uuid.UUID
	Role   entity.Role
}

// GetUserInfoByJWT retrieves the user information from the incoming context based on the
// JWT token in the authorization header.
//
// The function reads the metadata from the incoming context using metadata.FromIncomingContext.
// If the metadata is not provided, it returns an error with gRPC code `Unauthenticated` and
// message "metadata is not provided".
//
// The function then reads the authorization header from the metadata. If the authorization
// header is not provided or does not have the "Bearer " prefix, it returns an error with gRPC
// code `Unauthenticated` and message "authorization header is not provided" or
// "authorization header does not have bearer prefix" respectively.
//
// The function then extracts the JWT token from the authorization header after removing the
// "Bearer " prefix. It then calls the `CheckJWT` function to verify the token and get the user
// ID and role. If the token is not valid, it returns an error with gRPC code `Unauthenticated`
// and message "authorization header is not valid".
//
// If everything goes well, it returns the user information with the user ID and role.
func (a *AuthService) GetUserInfoByJWT(ctx context.Context) (userInfo UserInfo, err error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return UserInfo{}, status.Error(codes.Unauthenticated, "metadata is not provided")
	}

	authHeader, ok := md["authorization"]
	if !ok || len(authHeader) == 0 {
		return UserInfo{}, status.Error(codes.Unauthenticated, "authorization header is not provided")
	}

	bearerPrefix := "Bearer "
	if !strings.HasPrefix(authHeader[0], bearerPrefix) {
		return UserInfo{}, status.Error(codes.Unauthenticated, "authorization header does not have bearer prefix")
	}

	token := strings.TrimPrefix(authHeader[0], bearerPrefix)

	id, userRole, err := a.CheckJWT(ctx, token)
	if err != nil {
		return UserInfo{}, status.Error(codes.Unauthenticated, "authorization header is not valid")
	}

	userInfo = UserInfo{UserID: id, Role: userRole}

	return userInfo, nil
}

func (a *AuthService) IsUserExists(ctx context.Context, email string) (bool, error) {
	return a.repository.IsUserExists(ctx, email)
}

// GenTokens generates new refresh and access tokens for the given user.
//
// It generates a new refresh token with the user's id and a flag indicating that it's a
// refresh token as claims. It signs the token using the secret key from the JWT
// configuration and sets the expiration time to 2 weeks.
//
// It also generates a new access token with the user's id, email as
// claims. It sets the expiration time to 1 day.
//
// If something goes wrong, it returns an error.
//
// If everything goes well, it returns the new refresh and access tokens.
func (a *AuthService) genTokens(user *entity.User, op string) (refreshToken, accessToken string, err error) {
	operation := a.logger.WithOperation(op)

	operation.Info("generating refresh and access tokens", "user_id", user.ID)

	refToken, err := a.genRefreshToken(user)
	if err != nil {
		a.logger.Error("failed to generate refresh token", err, operation.AnyAttr("user_id", user.ID), operation.AnyAttr("user_id", user.ID))

		return "", "", errors.New("failed to generate refresh token")
	}

	operation.Info("refresh token generated", "user_id", user.ID, "refresh_token", refToken, "operation", operation)

	accToken, err := a.genAccessToken(user.ID, user.Role)
	if err != nil {
		operation.Error("failed to generate access token", err, "user_id", user.ID, "operation", operation)

		return "", "", errors.New("failed to generate access token")
	}

	operation.Info("access token generated", "user_id", user.ID, "access_token", accToken, "operation", operation)

	return refToken, accToken, nil
}

// genRefreshToken generates a new refresh token for the given user with their id and a flag
// indicating that it's a refresh token as claims. It signs the token using the secret key
// from the JWT configuration and sets the expiration time to 2 weeks.
func (a *AuthService) genRefreshToken(user *entity.User) (string, error) {
	const op = "genRefreshToken"
	operation := a.logger.WithOperation(op)

	operation.Info("generating refresh token", "user_id", user.ID)

	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.MapClaims{
			"id":         user.ID,
			"is_refresh": true,
			"exp":        time.Now().Add(config.NewJWTConfig().ExpireRefreshToken).Unix(),
		},
	)

	secretKey, err := a.getJWTSecretKey(user.Role)
	if err != nil {
		operation.Error("failed to get secret key", err, a.logger.AnyAttr("role", user.Role))

		return "", errors.New("failed to get secret key")
	}

	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		operation.Error("failed to sign refresh token", err, a.logger.AnyAttr("role", user.Role))

		return "", errors.New("failed to sign refresh token")
	}

	operation.Info("refresh token generated", "user_id", user.ID, "refresh_token", tokenString)

	return tokenString, nil
}

// genAccessToken generates a new access token for the given user with their ID as claims.
// It signs the token using the secret key from the environment variable and sets the
// expiration time to 24 hours.
func (a *AuthService) genAccessToken(id uuid.UUID, role entity.Role) (string, error) {
	const op = "genAccessToken"
	operation := a.logger.WithOperation(op)

	secretKey, err := a.getJWTSecretKey(role)
	if err != nil {
		operation.Error("failed to get secret key", err, a.logger.AnyAttr("role", role))

		return "", err
	}

	expireTime := a.configJWT.GetExpireAccessToken()

	operation.Debug("token expiration time", slog.Duration("expire_time", expireTime))

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  id,
		"exp": time.Now().Add(expireTime).Unix(),
	})

	signedToken, err := token.SignedString([]byte(secretKey))
	if err != nil {
		operation.Error("failed to sign token", err)

		return "", err
	}

	operation.Debug("generated access token", a.logger.AnyAttr("token", signedToken))

	return signedToken, nil
}

// GetUserByID retrieves a user by its ID from the database.
//
// It returns the user if found, nil if not found, or an error.
// If no matching user is found, it returns ErrUserNotFound.
// If a database error occurs, it is returned.
// If a user is found, it returns the user.
func (a *AuthService) GetUserByID(ctx context.Context, userID uuid.UUID) (*entity.User, error) {
	return a.repository.GetUserByID(ctx, userID)
}

// GetUserByToken retrieves a user by its access token.
//
// It parses the access token, validates it, and retrieves the corresponding user from
// the database. If the token is invalid or the user is not found, it returns an error.
//
// It is used to authenticate a user on subsequent requests. The access token is a JWT
// token that contains the user's ID, email.
//
// If a user is found, it returns the user.
func (a *AuthService) GetUserByToken(ctx context.Context, accessToken string) (*entity.User, error) {
	const op = "GetUserByToken"
	operation := a.logger.WithOperation(op)

	operation.Info("%s: received request", slog.LevelDebug)

	userID, _, err := a.CheckJWT(ctx, accessToken)
	if err != nil {
		operation.Error("%s: failed to check jwt", err)

		return nil, errors.New("failed to check jwt")
	}

	return a.repository.GetUserByID(ctx, userID)
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
func (a *AuthService) Register(ctx context.Context, user *entity.User) (entity.IAuthResponse, error) {
	const op = "Register"
	operation := a.logger.WithOperation(op)

	operation.Debug("input entity", user)

	if user == nil {
		operation.Error("input entity is nil", errors.New("input entity is nil"))

		return nil, apperrors.ErrInvalidCredentials
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		operation.Error("failed to generate password hash", err)

		return nil, errors.New("failed to generate password hash")
	}

	user.Password = string(hashedPassword)
	user.Role = entity.UserRole

	operation.Debug("registering user", user)

	userFromDB, err := a.repository.Register(ctx, user)
	if err != nil {
		operation.Error("failed to register user", err)

		return nil, fmt.Errorf("%s: %w", operation, err)
	}

	operation.Debug("saved user data for user", operation, user.ID)

	refreshToken, accessToken, err := a.genTokens(userFromDB, op)
	if err != nil {
		return nil, err
	}

	operation.Debug("successfully generated tokens for user", userFromDB)

	return entity.NewAuthResponse(refreshToken, accessToken, userFromDB.Role), nil
}

// Login authenticates a user by email and password. It retrieves the user from
// the repository, compares the password hash, and returns the user's tokens if valid.
//
// It returns the refresh token, access token, and the user's role.
//
// The refresh token is used to authenticate the user on subsequent requests.
// The access token is a JWT token that contains the user's ID, email.
// The role is the user's role in the system.
//
// It returns an error if something goes wrong during the login process.
// If the user credentials are invalid, it returns ErrInvalidCredentials.
func (a *AuthService) Login(ctx context.Context, user *entity.User) (entity.IAuthResponse, error) {
	const op = "Login"
	operation := a.logger.WithOperation(op)

	if user == nil {
		operation.Error("input entity is nil", errors.New("input entity is nil"))

		return nil, errors.New("input entity is nil")
	}

	userFromDB, err := a.repository.Login(ctx, user)
	if err != nil {
		operation.Error("failed to get user from DB", err)

		return nil, errors.New("failed to get user from DB")
	}

	if userFromDB == nil {
		operation.Error("user not found", apperrors.ErrInvalidCredentials)

		return nil, errors.New("user not found")
	}

	operation.Info("got user from DB", "id: ", userFromDB.ID)

	if err := bcrypt.CompareHashAndPassword([]byte(userFromDB.Password), []byte(user.Password)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			operation.Error("invalid credentials", err)

			return nil, errors.New("invalid credentials")
		}

		operation.Error("failed to compare password hash and plaintext password", err)

		return nil, errors.New("failed to compare password hash and plaintext password")
	}

	operation.Info("password hash and plaintext password match")

	refreshToken, accessToken, err := a.genTokens(userFromDB, op)
	if err != nil {
		operation.Error("failed to generate tokens", err)

		return nil, err
	}

	return entity.NewAuthResponse(accessToken, refreshToken, userFromDB.Role), nil
}

// parseToken parses the refresh token and returns the JWT token.
//
// It verifies the refresh token by decoding it and checking if it's a valid
// refresh token issued by this service. If it's valid, it gets the user from the
// database using the id in the token and returns the JWT token.
//
// If the refresh token is invalid or something goes wrong, it returns an error.
func (a *AuthService) parseToken(ctx context.Context, refToken string) (*jwt.Token, *entity.User, error) {
	const op = "parseToken"
	operation := a.logger.WithOperation(op)

	// Parse the token
	token, err := jwt.Parse(refToken, func(token *jwt.Token) (any, error) {
		// Validate the algorithm
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			operation.Error("unexpected signing method", errors.New("unexpected signing method"))

			return nil, errors.New("unexpected signing method")
		}

		// Extract claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			operation.Error("invalid token claims type", errors.New("invalid token claims type"))

			return nil, errors.New("invalid token claims type")
		}

		// Get the user ID from the token claims
		userID, ok := claims["id"].(float64)
		if !ok {
			operation.Error("user ID not found in token claims", errors.New("user ID not found"))

			return nil, errors.New("user ID not found")
		}

		uuidUserID, err := uuid.Parse(fmt.Sprintf("%v", userID))
		if err != nil {
			operation.Error("failed to parse user ID", err)

			return nil, err
		}

		// Get the user from the database using the user ID
		user, err := a.repository.GetUserByID(ctx, uuidUserID)
		if err != nil {
			operation.Error("failed to get user from DB", err)

			return nil, err
		}

		// Retrieve the secret key for the user's role
		secretKey, err := a.getJWTSecretKey(user.Role)
		if err != nil {
			operation.Error("failed to get JWT secret key", err)

			return nil, err
		}

		operation.Debug("got secret key for token validation", slog.String("secret_key", secretKey))

		// Return the secret key
		return []byte(secretKey), nil
	})
	if err != nil {
		operation.Error("failed to parse token", err)

		return nil, &entity.User{}, err
	}

	// Extract user ID from the token claims
	userID := uint64(token.Claims.(jwt.MapClaims)["id"].(float64))

	uuidUserID, err := uuid.Parse(fmt.Sprintf("%v", userID))
	if err != nil {
		operation.Error("failed to parse user ID", err)

		return nil, &entity.User{}, err
	}

	user, err := a.repository.GetUserByID(ctx, uuidUserID)
	if err != nil {
		operation.Error("failed to get user from DB", err)

		return nil, &entity.User{}, err
	}

	operation.Debug("got user from DB", user)

	// Return the JWT token and the user
	return token, user, nil
}

// Refresh generates a new access token using the provided refresh token.
//
// It verifies the refresh token by decoding it and checking if it's a valid
// refresh token issued by this service. If it's valid, it gets the user from the
// database using the id in the token and generates a new access token for the user.
//
// If the refresh token is invalid or something goes wrong, it returns an error.
func (a *AuthService) Refresh(ctx context.Context, refToken string) (accessToken, refreshToken string, err error) {
	const op = "Refresh"
	operation := a.logger.WithOperation(op)

	operation.Info("checking refresh token", "refresh_token", refToken)

	var user *entity.User

	token, user, err := a.parseToken(ctx, refToken)
	if err != nil {
		var ve *jwt.ValidationError
		if errors.As(err, &ve) {
			switch {
			case ve.Errors&jwt.ValidationErrorMalformed != 0:
				operation.Debug("refresh token is malformed", err)

				err = apperrors.ErrInvalidAccessTokenMalformed
			case ve.Errors&jwt.ValidationErrorExpired != 0:
				operation.Debug("refresh token is expired", err)

				err = apperrors.ErrInvalidAccessTokenExpired
			default:
				operation.Warn("invalid refresh token", err)

				err = apperrors.ErrInvalidAccessToken
			}
		}

		return "", "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		operation.Warn("invalid refresh token claims", "claims", claims, "token_valid", token.Valid)

		return "", "", apperrors.ErrInvalidAccessToken
	}

	isRefresh, ok := claims["is_refresh"].(bool)
	if !ok || !isRefresh {
		operation.Error("invalid refresh token", apperrors.ErrInvalidRefreshToken)

		return "", "", fmt.Errorf("%s: %w", operation, apperrors.ErrInvalidRefreshToken)
	}

	refreshToken, accessToken, err = a.genTokens(user, op)
	if err != nil {
		operation.Error("failed to generate tokens", err)

		return "", "", fmt.Errorf("%s: %w", operation, err)
	}

	operation.Info("tokens generated", "refresh_token", refreshToken, "access_token", accessToken)

	return accessToken, refreshToken, nil
}

// CheckJWT validates the access token by decoding it and checking if it's a valid
// access token. If it's valid, it returns the id of the user that the token belongs to.
//
// If the access token is invalid or something goes wrong, it returns an error.
func (a *AuthService) CheckJWT(ctx context.Context, accessToken string) (id uuid.UUID, userRole entity.Role, err error) {
	const op = "CheckJWT"
	operation := a.logger.WithOperation(op)

	operation.Info("checking access token", "access_token", accessToken)

	var user *entity.User

	_, user, err = a.parseToken(ctx, accessToken)
	if err != nil {
		if errors.As(err, new(jwt.ValidationError)) {
			a.logger.Error("invalid access token", err)

			var ve *jwt.ValidationError
			if errors.As(err, &ve) {
				switch {
				case ve.Errors&jwt.ValidationErrorMalformed != 0:
					operation.Info("access token is malformed", "error", err)

					err = apperrors.ErrInvalidAccessTokenMalformed
				case ve.Errors&jwt.ValidationErrorExpired != 0:
					operation.Info("access token is expired", "error", err)

					err = apperrors.ErrInvalidAccessTokenExpired
				default:
					operation.Warn("invalid access token", "error", err)

					err = apperrors.ErrInvalidAccessToken
				}
			}
		}

		return uuid.Nil, "", err
	}

	return user.ID, user.Role, nil
}

// SearchByEmail retrieves a user by its email
//
// It searches for a user in the database using the given email.
// If a user is found, it returns the user.
// If no matching user is found, it returns ErrUserNotFound.
// If a database error occurs, it is returned.
// If a user is found, it returns the user.
func (a *AuthService) SearchByEmail(ctx context.Context, email string) ([]*entity.User, error) {
	email = strings.Trim(strings.ToLower(email), " ")

	return a.repository.SearchByEmail(ctx, email)
}

// ChangeRole updates a user's role in the database.
//
// It updates the role of the user with the given ID to the given role.
// If the user is not found, it returns ErrUserNotFound.
// If a database error occurs, it is returned.
// If the user is updated, it returns nil.
func (a *AuthService) ChangeRole(ctx context.Context, userID uuid.UUID, role entity.Role) error {
	const op = "ChangeRole"
	operation := a.logger.WithOperation(op)

	operation.Info("changing user role", "user_id", userID, "role", role)

	usr, err := a.repository.GetUserByID(ctx, userID)
	if err != nil {
		operation.Error("failed to get user", err)

		return err
	}

	if usr.Role == entity.AdminRole {
		operation.Error("cannot change admin role", errors.New("cannot change admin role"))

		return apperrors.ErrCannotChangeAdminRole
	}

	operation.Info("updating user role in database", "user_id", userID, "role", role)

	err = a.repository.Update(ctx, &entity.User{ID: userID, Role: role, UpdatedAt: time.Now()})
	if err != nil {
		operation.Error("failed to update user", err)

		return err
	}

	return nil
}

// GetByRole retrieves users by their role
//
// It returns all users with the given role.
// If no users are found, it returns an empty slice.
// If a database error occurs, it is returned.
// If users are found, it returns the users.
func (a *AuthService) GetByRole(ctx context.Context, role entity.Role) ([]*entity.User, error) {
	return a.repository.GetByRole(ctx, role)
}
