package signing_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wostzone/hubapi-go/pkg/signing"
)

const privKeyPemFile = "../../test/certs/privKey.pem"

func TestSaveLoadPrivKey(t *testing.T) {
	privKey := signing.CreateECDSAKeys()
	err := signing.SavePrivateKeyToPEM(privKey, privKeyPemFile)
	assert.NoError(t, err)

	privKey2, err := signing.LoadPrivateKeyFromPEM(privKeyPemFile)
	assert.NoError(t, err)
	assert.NotNil(t, privKey2)
}

func TestSaveLoadPrivKeyNotFound(t *testing.T) {
	privKey := signing.CreateECDSAKeys()
	// no access
	err := signing.SavePrivateKeyToPEM(privKey, "/root")
	assert.Error(t, err)

	//
	privKey2, err := signing.LoadPrivateKeyFromPEM("/root")
	assert.Error(t, err)
	assert.Nil(t, privKey2)
}

func TestPublicKeyPEM(t *testing.T) {
	privKey := signing.CreateECDSAKeys()

	pem, err := signing.PublicKeyToPEM(&privKey.PublicKey)

	assert.NoError(t, err)
	assert.NotEmpty(t, pem)

	pubKey, err := signing.PublicKeyFromPEM(pem)
	assert.NoError(t, err)
	assert.NotNil(t, pubKey)

	isEqual := privKey.PublicKey.Equal(pubKey)
	assert.True(t, isEqual)
}

func TestPrivateKeyPEM(t *testing.T) {
	privKey := signing.CreateECDSAKeys()

	pem, err := signing.PrivateKeyToPEM(privKey)

	assert.NoError(t, err)
	assert.NotEmpty(t, pem)

	privKey2, err := signing.PrivateKeyFromPEM(pem)
	assert.NoError(t, err)
	assert.NotNil(t, privKey2)

	isEqual := privKey.Equal(privKey2)
	assert.True(t, isEqual)
}

func TestInvalidPEM(t *testing.T) {
	privKey, err := signing.PrivateKeyFromPEM("PRIVATE KEY")
	assert.Error(t, err)
	assert.Nil(t, privKey)

	pubKey, err := signing.PublicKeyFromPEM("PUBLIC KEY")
	assert.Error(t, err)
	assert.Nil(t, pubKey)
}
