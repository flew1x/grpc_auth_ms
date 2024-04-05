package grpcauth

import (
	"context"
	"errors"
	"msauth/internal/api/grpc_api"
	"msauth/internal/custom_errors"
	"msauth/internal/entity"
	"msauth/internal/service"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type authServerAPI struct {
	grpc_api.UnimplementedAuthServer
	service service.Service
}

// RegisterServer registers the given AuthServerAPI instance with the provided
// gRPC server. This allows the gRPC server to serve the auth related RPCs.
func RegisterServer(grpcServer *grpc.Server, service service.Service) {
	grpc_api.RegisterAuthServer(grpcServer, &authServerAPI{service: service})
}

// Register registers a new user. It validates the input, creates a User entity,
// calls the AuthService's Register method, and handles any errors by returning
// a gRPC error status. The token is returned on success.
func (s *authServerAPI) Register(ctx context.Context, in *grpc_api.RegisterRequest) (*grpc_api.AuthResponse, error) {
	switch {
	case len(in.GetEmail()) == 0:
		return nil, status.Error(codes.InvalidArgument, "email is required")
	case len(in.GetPassword()) == 0:
		return nil, status.Error(codes.InvalidArgument, "password is required")
	default:
		break
	}

	user := &entity.User{
		Email:    in.GetEmail(),
		Password: in.GetPassword(),
	}

	authResp, err := s.service.AuthService.Register(ctx, user)
	if err != nil {
		switch {
		case errors.Is(err, custom_errors.ErrUserExists):
			return nil, status.Error(codes.InvalidArgument, "user already exists")
		case errors.Is(err, custom_errors.ErrInvalidCredentials):
			return nil, status.Error(codes.InvalidArgument, "invalid credentials")
		default:
			return nil, status.Error(codes.Internal, "failed to register")
		}
	}

	return &grpc_api.AuthResponse{RefreshToken: authResp.RefreshToken, AccessToken: authResp.AccessToken, Role: string(authResp.Role)}, nil
}

// Login handles user login requests. It validates the input, checks
// credentials against the data store, and returns a token on success.
// Possible error cases include missing email/phone, missing password,
// invalid credentials, and internal errors.
func (s *authServerAPI) Login(ctx context.Context, in *grpc_api.LoginRequest) (*grpc_api.AuthResponse, error) {
	switch {
	case len(in.GetEmail()) == 0:
		return nil, status.Error(codes.InvalidArgument, "email is required")
	case len(in.GetPassword()) == 0:
		return nil, status.Error(codes.InvalidArgument, "password is required")
	default:
		break
	}

	user := &entity.User{
		Email:    in.GetEmail(),
		Password: in.GetPassword(),
	}

	authResp, err := s.service.AuthService.Login(ctx, user)
	if err != nil {
		switch {
		case errors.Is(err, custom_errors.ErrUserNotFound):
			return nil, status.Error(codes.InvalidArgument, "user not found")
		case errors.Is(err, custom_errors.ErrInvalidCredentials):
			return nil, status.Error(codes.InvalidArgument, "invalid credentials")
		default:
			return nil, status.Error(codes.Internal, "failed to login")
		}
	}

	return &grpc_api.AuthResponse{RefreshToken: authResp.RefreshToken, AccessToken: authResp.AccessToken, Role: string(authResp.Role)}, nil
}

// Refresh handles token refresh requests. It validates the input, checks the
// refresh token against the data store, and returns a new access token on
// success. Possible error cases include missing refresh token, invalid refresh
// token, and internal errors.
//
// The refresh token is validated using the following rules:
//
// - The token is not empty.
// - The token is properly formatted.
// - The token has not expired.
// - The token corresponds to a valid refresh token entry in the data store.
//
// If the token is valid, a new access token is generated and returned in the
// response. The new access token has the same expiration as the original token.
//
// If the token is not valid, an error is returned with a gRPC status code and
// message indicating the error. The possible error cases are:
//
// - InvalidArgument: The refresh token is empty or malformed.
// - InvalidArgument: The refresh token has expired.
// - InvalidArgument: The refresh token is not found in the data store.
// - Internal: Failed to refresh token due to an internal error.
func (s *authServerAPI) Refresh(ctx context.Context, in *grpc_api.RefreshRequest) (*grpc_api.RefreshResponse, error) {
	refreshToken := in.GetRefreshToken()
	role := entity.UserRole(in.GetRole())
	if len(refreshToken) == 0 || role == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh token and role is required")
	}

	accessToken, refreshToken, err := s.service.AuthService.Refresh(ctx, refreshToken, role)
	if err != nil {
		switch {
		case errors.Is(err, custom_errors.ErrInvalidRefreshToken):
			return nil, status.Error(codes.InvalidArgument, "invalid refresh token")
		case errors.Is(err, custom_errors.ErrInvalidRefreshTokenExpired):
			return nil, status.Error(codes.InvalidArgument, "refresh token expired")
		case errors.Is(err, custom_errors.ErrInvalidRefreshTokenMalformed):
			return nil, status.Error(codes.InvalidArgument, "invalid refresh token malformed")
		default:
			return nil, status.Error(codes.Internal, "failed to refresh token")
		}
	}

	return &grpc_api.RefreshResponse{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

// CheckJWTSecretKey validates the input access token and role,
// and checks the access token against the data store using the
// AuthService's CheckJWTSecretKey method. Possible error cases
// include missing role or access token, and internal errors.
//
// The access token is validated using the following rules:
//
// - The token is not empty.
// - The token is properly formatted.
// - The token has not expired.
// - The token corresponds to a valid access token entry in the data store.
//
// If the token is valid, the user ID is returned in the response.
//
// If the token is not valid, an error is returned with a gRPC status code and
// message indicating the error. The possible error cases are:
//
// - InvalidArgument: The access token or role is empty.
// - Internal: Failed to check JWT secret key due to an internal error.
func (s *authServerAPI) CheckJWT(ctx context.Context, in *grpc_api.CheckJWTRequest) (*grpc_api.CheckJWTResponse, error) {
	role := entity.UserRole(in.GetRole())
	accessToken := in.GetToken()
	if role == "" || len(accessToken) == 0 {
		return nil, status.Error(codes.InvalidArgument, "role and access token is required")
	}

	valid, id, err := s.service.AuthService.CheckJWT(ctx, accessToken, role)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to check jwt secret key")
	}

	return &grpc_api.CheckJWTResponse{Valid: valid, UserId: id.String()}, nil
}
