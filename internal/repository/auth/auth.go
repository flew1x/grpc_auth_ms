package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"msauth/internal/custom_errors"
	"msauth/internal/entity"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

type IAuthRespository interface {
    Register(ctx context.Context, user *entity.User) (*entity.User, error)
    Login(ctx context.Context, user *entity.User) (*entity.User, error)
    GetUserByID(ctx context.Context, userID uuid.UUID) (*entity.User, error)
}

type authRespository struct {
    db *bun.DB
}

func NewAuthRespository(db *bun.DB) IAuthRespository {
    return &authRespository{ db: db }
}

// Register registers a new user account.
// It checks if a user with the same email or phone already exists.
// If no existing user is found, it inserts the new user into the database.
// Possible errors:
// - ErrUserExists if a user with the same email or phone was found.
// - Database errors from insert operation.
func (a *authRespository) Register(ctx context.Context, user *entity.User) (*entity.User, error) {
    userCount, err := a.db.NewSelect().Model(user).Where("email = ?", user.Email).Count(ctx)
    if err != nil {
        return nil, fmt.Errorf("cannot count users: %v", err)
    }

    switch userCount {
    case 0:
        if _, err := a.db.NewInsert().Model(user).Ignore().Exec(ctx); err != nil {
            return nil, err
        }
    case 1:
        return nil, custom_errors.ErrUserExists
    default:
        return nil, fmt.Errorf("found multiple users with id %d", user.ID)
    }

    return user, nil
}

// Login authenticates a user by email/phone and password.
// It returns the authenticated user if found, nil if not found, or an error.
// It first queries the db to find a user matching the email/phone.
// If no matching user is found, it returns ErrUserNotFound.
// If a database error occurs, it is returned.
// If a user is found, it returns a new copy of the user.
func (a *authRespository) Login(ctx context.Context, user *entity.User) (*entity.User, error) {
    var userFromDB entity.User

    if err := a.db.NewSelect().Model(&userFromDB).Where(`email = ?`, user.Email).Scan(ctx); err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            return nil, custom_errors.ErrUserNotFound
        }
        return nil, err
    }

    return &userFromDB, nil
}

// GetUserByID retrieves a user by its ID.
// It returns the user if found, nil if not found, or an error.
// If no matching user is found, it returns ErrUserNotFound.
// If a database error occurs, it is returned.
// If a user is found, it returns the user.
func (a *authRespository) GetUserByID(ctx context.Context, userID uuid.UUID) (*entity.User, error) {
    user := new(entity.User)

    if err := a.db.NewSelect().Model(user).Where("id = ?", userID).Scan(ctx); err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            return nil, custom_errors.ErrUserNotFound
        }
        return nil, err
    }

    return user, nil
}