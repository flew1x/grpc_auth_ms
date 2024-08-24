package entity

import (
	"time"

	uuid "github.com/google/uuid"
	"github.com/uptrace/bun"
)

type Role string

const (
	AdminRole   Role = "ADMIN"
	UserRole    Role = "USER"
	SuperRole   Role = "SUPER"
	BlockedRole Role = "BLOCKED"
)

func (r Role) String() string {
	return string(r)
}

// User - represents a user in the database
// User represents a user in the database.
type User struct {
	// bun.BaseModel provides default primary key `id` field and `created_at`, `updated_at` and `deleted_at` fields.
	bun.BaseModel `bun:"table:users"`

	// ID is a unique identifier of the user.
	ID uuid.UUID `bun:"id,pk,type:uuid,default:gen_random_uuid()" json:"id"`

	// Email is an email address of the user.
	Email string `bun:"email,notnull" json:"email"`

	// Password is a password of the user.
	Password string `bun:"password,notnull" json:"password,omitempty"`

	// Role is a role of the user.
	Role Role `bun:"role,notnull" json:"role"`

	// CreatedAt is a time when the user was created.
	CreatedAt time.Time `bun:"created_at,nullzero,notnull,default:now()" json:"createdAt"`

	// UpdatedAt is a time when the user was last updated.
	UpdatedAt time.Time `bun:"updated_at,nullzero,notnull,default:now()" json:"updatedAt"`

	// DeletedAt is a time when the user was deleted (if not null).
	DeletedAt time.Time `bun:"deleted_at,soft_delete" json:"-"`
}
