package tlsserver_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wostzone/wostlib-go/pkg/tlsserver"
)

// JWT test cases for 100% coverage
func TestJWTToken(t *testing.T) {
	user1 := "user1"
	jauth := tlsserver.NewJWTAuthenticator(nil, func(login, pass string) error {
		assert.Fail(t, "Should never reach here")
		return nil
	})
	expTime := time.Now().Add(time.Second * 100)
	accessToken, refreshToken, err := jauth.CreateJWTTokens("user1", expTime)
	assert.NoError(t, err)

	jwtToken, claims, err := jauth.DecodeToken(accessToken)
	_ = jwtToken
	require.NoError(t, err)
	assert.Equal(t, user1, claims.Username)

	jwtToken, claims, err = jauth.DecodeToken(refreshToken)
	_ = jwtToken
	require.NoError(t, err)
	assert.Equal(t, user1, claims.Username)
}

func TestJWTNotWostToken(t *testing.T) {
	user1 := "user1"
	secret := []byte("notreallyasecret")

	jauth := tlsserver.NewJWTAuthenticator(secret, func(login, pass string) error {
		assert.Fail(t, "Should never reach here")
		return nil
	})

	claims1 := jwt.StandardClaims{Id: user1}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims1)
	// construct a token with the right secret but a different struct type
	signedToken, err := token.SignedString(secret)
	assert.NoError(t, err)
	jwtToken, claim2, err := jauth.DecodeToken(signedToken)
	_ = jwtToken
	// apparently this still works
	require.NoError(t, err)
	assert.Equal(t, user1, claim2.Id)
}

// start with a val

// additional JWT test cases for 100% coverage
func TestJWTBadToken(t *testing.T) {
	jauth := tlsserver.NewJWTAuthenticator(nil, func(login, pass string) error {
		assert.Fail(t, "Should never reach here")
		return nil
	})

	// start with a valid access token
	req, _ := http.NewRequest("GET", "badurl", nil)
	expTime := time.Now().Add(time.Second * 100)
	accessToken, refreshToken, err := jauth.CreateJWTTokens("user1", expTime)
	assert.NoError(t, err)
	assert.NotNil(t, accessToken)
	assert.NotNil(t, refreshToken)
	req.Header.Add("Authorization", "bearer "+accessToken)
	err = jauth.AuthenticateRequest(nil, req)
	assert.NoError(t, err)

	// missing auth token
	req = &http.Request{}
	err = jauth.AuthenticateRequest(nil, req)
	assert.Error(t, err)

	// invalid auth header
	req, _ = http.NewRequest("GET", "badurl", nil)
	req.Header.Add("Authorization", "")
	err = jauth.AuthenticateRequest(nil, req)
	assert.Error(t, err)

	// incomplete bearer token
	req, _ = http.NewRequest("GET", "badurl", nil)
	req.Header.Add("Authorization", "bearer")
	err = jauth.AuthenticateRequest(nil, req)
	assert.Error(t, err)

	// invalid bearer token
	req, _ = http.NewRequest("GET", "badurl", nil)
	req.Header.Add("Authorization", "bearer invalidtoken")
	err = jauth.AuthenticateRequest(nil, req)
	assert.Error(t, err)
}

func TestBadLogin(t *testing.T) {
	jauth := tlsserver.NewJWTAuthenticator(nil, func(login, pass string) error {
		assert.Fail(t, "Should never reach here")
		return nil
	})
	body := http.NoBody
	req, err := http.NewRequest("GET", "someurl", body)
	assert.NoError(t, err)
	resp := httptest.NewRecorder()
	jauth.HandleJWTLogin(resp, req)
}
