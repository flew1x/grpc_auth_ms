package entity

// AuthResponse represents an authentication response.
type AuthResponse struct {
	// AccessToken is an access token that provides access to protected resources.

	AccessToken string `json:"access_token"`

	// RefreshToken is a refresh token that can be used to get a new pair of access and refresh tokens.
	RefreshToken string `json:"refresh_token"`
	
	// Role is an optional role of the user.
	Role UserRole `json:"role"`
}
