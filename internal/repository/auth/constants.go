package auth

const (
	EmailExistsQuery = "email = ? AND deleted_at = '0001-01-01 00:00:00+00:00'"
	PhoneExistsQuery = "phone = ? AND deleted_at = '0001-01-01 00:00:00+00:00'"
)
