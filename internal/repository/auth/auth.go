package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"msauth/internal/apperrors"
	"msauth/internal/entity"
	"msauth/pkg/logger"

	"github.com/uptrace/bun"
)

// IAuthRepository is an interface that defines the methods of the Auth repository.
type IAuthRepository interface {
	// Register registers a new user account.
	// It checks if a user with the same email already exists.
	// If no existing user is found, it inserts the new user into the database.
	// Possible errors:
	// - ErrUserExists if a user with the same email was found.
	// - Database errors from insert operation.
	Register(ctx context.Context, user *entity.User) (*entity.User, error)

	// Login authenticates a user by email and password.
	// It returns the authenticated user if found, nil if not found, or an error.
	// It first queries the db to find a user matching the email.
	// If no matching user is found, it returns ErrUserNotFound.
	// If a database error occurs, it is returned.
	// If a user is found, it returns a new copy of the user.
	Login(ctx context.Context, user *entity.User) (*entity.User, error)

	// GetUserByID retrieves a user by its ID.
	// It returns the user if found, nil if not found, or an error.
	// If no matching user is found, it returns ErrUserNotFound.
	// If a database error occurs, it is returned.
	// If a user is found, it returns the user.
	GetUserByID(ctx context.Context, userID uuid.UUID) (*entity.User, error)

	// SearchByEmail retrieves all users with the given email.
	// It returns all users with the given email, or an error if the query failed.
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

	// Update updates an existing user.
	//
	// It updates all fields that are not zero values.
	// It uses the user's ID as the WHERE condition for the update.
	//
	// Returns an error if the update operation failed.
	// If no user was found with the given ID, it returns ErrUserNotFound.
	Update(ctx context.Context, user *entity.User) error

	// Delete deletes a user by its ID.
	//
	// It deletes the user from the database.
	// It uses the user's ID as the WHERE condition for the delete operation.
	//
	// Returns an error if the delete operation failed.
	// If no user was found with the given ID, it returns ErrUserNotFound.
	// If a database error occurs, it is returned.
	Delete(ctx context.Context, userID uuid.UUID) error

	// IsUserExists checks if a user with the given email exists.
	// It returns true if a user with the given email exists, false otherwise.
	// If a database error occurs, it is returned.
	IsUserExists(ctx context.Context, email string) (bool, error)

	// GetByEmail retrieves a user by its email.
	// It returns the user if found, nil if not found, or an error.
	// If no matching user is found, it returns ErrUserNotFound.
	// If a database error occurs, it is returned.
	GetByEmail(ctx context.Context, email string) (*entity.User, error)
}

type Repository struct {
	db     *bun.DB
	logger logger.Logger
}

func NewRepository(logger logger.Logger, db *bun.DB) *Repository {
	return &Repository{
		db:     db,
		logger: logger,
	}
}

// Register registers a new user account.
// It checks if a user with the same email already exists.
// If no existing user is found, it inserts the new user into the database.
// Possible errors:
// - ErrUserExists if a user with the same email was found.
// - Database errors from insert operation.
func (a *Repository) Register(ctx context.Context, user *entity.User) (*entity.User, error) {
	const op = "Register"
	operation := a.logger.WithOperation(op)

	operation.Debug("registering user", a.logger.AnyAttr("user", user))

	exists, err := a.IsUserExists(ctx, user.Email)
	if err != nil {
		operation.Error("cannot check if user exists", err)

		return nil, err
	}

	if exists {
		operation.Warn("user already exists")

		return nil, apperrors.ErrUserExists
	}

	operation.Debug("user does not exist")

	if _, err := a.db.NewInsert().Model(user).Ignore().Returning("id").Exec(ctx); err != nil {
		operation.Error("cannot insert user", err)

		return nil, err
	}

	operation.Debug("user created", "user", user)

	return user, nil
}

// Update updates an existing user.
//
// It updates all fields that are not zero values.
// It uses the user's ID as the WHERE condition for the update.
//
// Returns an error if the update operation failed.
// If no user was found with the given ID, it returns ErrUserNotFound.
func (a *Repository) Update(ctx context.Context, user *entity.User) error {
	const op = "Update"
	operation := a.logger.WithOperation(op)

	_, err := a.db.NewUpdate().Model(user).OmitZero().WherePK().Exec(ctx)
	if err != nil {
		operation.Error("cannot update user", err)

		return err
	}

	return nil
}

// Delete deletes a user by its ID.
//
// It deletes the user from the database.
// It uses the user's ID as the WHERE condition for the delete operation.
//
// Returns an error if the delete operation failed.
// If no user was found with the given ID, it returns ErrUserNotFound.
// If a database error occurs, it is returned.
func (a *Repository) Delete(ctx context.Context, userID uuid.UUID) error {
	const op = "Delete"
	operation := a.logger.WithOperation(op)

	var user entity.User

	user.ID = userID

	_, err := a.db.NewDelete().Model(&user).WherePK().Exec(ctx)
	if err != nil {
		operation.Error("cannot delete user", err)

		return err
	}

	return nil
}

// Login authenticates a user by email and password.
// It returns the authenticated user if found, nil if not found, or an error.
// It first queries the db to find a user matching the email.
// If no matching user is found, it returns ErrUserNotFound.
// If a database error occurs, it is returned.
// If a user is found, it returns a new copy of the user.
func (a *Repository) Login(ctx context.Context, user *entity.User) (*entity.User, error) {
	const op = "Login"
	operation := a.logger.WithOperation(op)

	var userFromDB entity.User

	if err := a.db.NewSelect().Model(&userFromDB).Where(`email = ?`, user.Email).Scan(ctx); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			operation.Warn("user not found", a.logger.AnyAttr("user", user))

			return nil, apperrors.ErrUserNotFound
		}

		operation.Error("cannot get user", err)

		return nil, err
	}

	return &userFromDB, nil
}

// GetUserByID retrieves a user by its ID.
// It returns the user if found, nil if not found, or an error.
// If no matching user is found, it returns ErrUserNotFound.
// If a database error occurs, it is returned.
// If a user is found, it returns the user.
func (a *Repository) GetUserByID(ctx context.Context, userID uuid.UUID) (*entity.User, error) {
	const op = "GetUserByID"
	operation := a.logger.WithOperation(op)

	user := new(entity.User)

	if err := a.db.NewSelect().Model(user).
		Where("id = ?", userID).Scan(ctx); err != nil {
		operation.Error("cannot get user", err)

		if errors.Is(err, sql.ErrNoRows) {
			operation.Warn("user not found", "user_id", userID)

			return nil, apperrors.ErrUserNotFound
		}

		return nil, err
	}

	return user, nil
}

// GetByRole retrieves all users with the given role.
//
// It returns all users with the given role, or an error if the query failed.
// If no user was found, it returns an empty slice, not an error.
// If a database error occurs, it is returned.
// If users are found, it returns the users.
func (a *Repository) GetByRole(ctx context.Context, role entity.Role) ([]*entity.User, error) {
	const op = "GetByRole"
	operation := a.logger.WithOperation(op)

	var users []*entity.User

	if err := a.db.NewSelect().Model(&users).Where("role = ?", role).Scan(ctx); err != nil {
		operation.Error("cannot get users by role", err)

		if errors.Is(err, sql.ErrNoRows) {
			operation.Warn("users not found", "role", role)

			return nil, nil
		}

		return nil, err
	}

	return users, nil
}

// SearchByEmail retrieves a user by its email.
//
// It searches for a user with the given email using the ILIKE operator.
// The search is case-insensitive, and it matches users with a similar email.
// If no matching user is found, it returns nil, nil.
// If a database error occurs, it is returned.
// If a user is found, it returns the user.
func (a *Repository) SearchByEmail(ctx context.Context, email string) ([]*entity.User, error) {
	var users []*entity.User

	if err := a.db.NewSelect().Model(&users).
		Where("email ILIKE ?", fmt.Sprintf("%%%s%%", email)).Scan(ctx); err != nil {
		return nil, err
	}

	return users, nil
}

// IsUserExists checks if a user with the given email exists.
//
// It returns true if a user with the given email exists, false otherwise.
// If a database error occurs, it is returned.
//
// This function is useful for checking if a user exists before creating a new one.
func (a *Repository) IsUserExists(ctx context.Context, email string) (bool, error) {
	const op = "IsUserExists"
	operation := a.logger.WithOperation(op)

	operation.Info("checking if user exists", "email", email)

	var user entity.User

	if err := a.db.NewSelect().Model(&user).
		Where(EmailExistsQuery, email).Limit(1).Scan(ctx); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}

		operation.Error("cannot check if user exists", err)

		return false, err
	}

	return true, nil
}

func (a *Repository) GetByEmail(ctx context.Context, email string) (*entity.User, error) {
	const op = "GetByEmail"
	operation := a.logger.WithOperation(op)

	user := new(entity.User)

	if err := a.db.NewSelect().Model(user).
		Where("email = ?", email).Scan(ctx); err != nil {
		operation.Error("cannot get user", err)

		if errors.Is(err, sql.ErrNoRows) {
			operation.Warn("user not found", "email", email)

			return nil, apperrors.ErrUserNotFound
		}

		return nil, err
	}

	return user, nil
}
