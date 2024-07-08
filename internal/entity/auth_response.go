package entity

type IAuthResponse interface {
	// GetAccessToken returns the access token.
	GetAccessToken() string

	// GetRefreshToken returns the refresh token.
	GetRefreshToken() string

	// GetRole returns the role.
	GetRole() string
}

// AuthResponse represents the response from the authentication service.
type AuthResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	Role         string `json:"role"`
}

// NewAuthResponse creates a new AuthResponse.
func NewAuthResponse(accessToken, refreshToken string, role Role) *AuthResponse {
	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Role:         string(role),
	}
}

func (a *AuthResponse) GetRole() string {
	return a.Role
}

func (a *AuthResponse) GetAccessToken() string {
	return a.AccessToken
}

func (a *AuthResponse) GetRefreshToken() string {
	return a.RefreshToken
}
