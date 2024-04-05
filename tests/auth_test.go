package tests

import (
	"msauth/internal/api/grpc_api"
	"msauth/tests/suite"
	"testing"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const defaultPasswordLength = 10

func genPassword() string {
	return gofakeit.Password(true, true, true, true, false, defaultPasswordLength)
}

func TestRegister_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	password := genPassword()

	user := &grpc_api.RegisterRequest{
		Email:    email,
		Password: password,
	}

	respReg, err := st.AuthClient.Register(ctx, user)
	
	require.NoError(t, err)
	assert.NotEmpty(t, respReg.AccessToken)
	assert.NotEmpty(t, respReg.RefreshToken)
	assert.NotEmpty(t, respReg.Role)
}


func TestLogin_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	password := genPassword()

	userReg := &grpc_api.RegisterRequest{
		Email:    email,
		Password: password,
	}

	_, err := st.AuthClient.Register(ctx, userReg)
	require.NoError(t, err)

	userLog := &grpc_api.LoginRequest{
		Email:    email,
		Password: password,
	}

	respLogin, err := st.AuthClient.Login(ctx, userLog)
	require.NoError(t, err)

	assert.NotEmpty(t, respLogin.AccessToken)
	assert.NotEmpty(t, respLogin.RefreshToken)
	assert.NotEmpty(t, respLogin.Role)
}

func TestCheckJWT_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	password := genPassword()

	userReg := &grpc_api.RegisterRequest{
		Email:    email,
		Password: password,
	}

	_, err := st.AuthClient.Register(ctx, userReg)
	require.NoError(t, err)

	userLog := &grpc_api.LoginRequest{
		Email:    email,
		Password: password,
	}

	respLogin, err := st.AuthClient.Login(ctx, userLog)
	require.NoError(t, err)

	assert.NotEmpty(t, respLogin.AccessToken)
	assert.NotEmpty(t, respLogin.RefreshToken)
	assert.NotEmpty(t, respLogin.Role)

	respCheck, err := st.AuthClient.CheckJWT(ctx, &grpc_api.CheckJWTRequest{
		Token: respLogin.AccessToken,
		Role:        respLogin.Role,
	})

	require.NoError(t, err)

	assert.True(t, respCheck.Valid)
	assert.NotEmpty(t, respCheck.UserId)
}

func TestRefreshToken_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	password := genPassword()

	userReg := &grpc_api.RegisterRequest{
		Email:    email,
		Password: password,
	}

	_, err := st.AuthClient.Register(ctx, userReg)
	require.NoError(t, err)

	userLog := &grpc_api.LoginRequest{
		Email:    email,
		Password: password,
	}

	respLogin, err := st.AuthClient.Login(ctx, userLog)
	require.NoError(t, err)

	assert.NotEmpty(t, respLogin.AccessToken)
	assert.NotEmpty(t, respLogin.RefreshToken)
	assert.NotEmpty(t, respLogin.Role)

	respRefresh, err := st.AuthClient.Refresh(ctx, &grpc_api.RefreshRequest{
		RefreshToken: respLogin.RefreshToken,
		Role:         respLogin.Role,
	})
	require.NoError(t, err)

	assert.NotEmpty(t, respRefresh.AccessToken)
	assert.NotEmpty(t, respRefresh.RefreshToken)
}