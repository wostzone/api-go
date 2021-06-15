// Package certsetup with creation of self signed certificate chain using ECDSA signing
// Credits: https://gist.github.com/shaneutt/5e1995295cff6721c89a71d13a71c251
package certsetup

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
	"net"
	"path"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/wostzone/hubapi-go/api"
	"github.com/wostzone/hubapi-go/pkg/signing"
)

// const keySize = 2048 // 4096
const caDefaultValidityDuration = time.Hour * 24 * 364 * 10 // 10 years
const caTemporaryValidityDuration = time.Hour * 24 * 3      // 3 days

// const certDurationYears = 10
const DefaultCertDuration = time.Hour * 24 * 365
const TempCertDuration = time.Hour * 24 * 1

// Standard client and server certificate filenames all stored in PEM format
const (
	CaCertFile     = "caCert.pem" // CA that signed the server and client certificates
	CaKeyFile      = "caKey.pem"
	ServerCertFile = "hubCert.pem"
	ServerKeyFile  = "hubKey.pem"
	ClientCertFile = "clientCert.pem"
	ClientKeyFile  = "clientKey.pem"
)

// CreateCertificateBundle is a convenience function to create the Hub CA, server and (plugin) client
// certificates into the given folder. Intended for testing.
// This only creates missing certificates.
func CreateCertificateBundle(hostname string, certFolder string) error {
	var err error
	// create the CA if needed
	caCertPEM, _ := ReadPEM(certFolder, CaCertFile)
	caKeyPEM, _ := ReadPEM(certFolder, CaKeyFile)
	if caCertPEM == "" || caKeyPEM == "" {
		caCertPEM, caKeyPEM = CreateHubCA()
		err = WriteKeyPEM(caKeyPEM, certFolder, CaKeyFile)
		if err != nil {
			logrus.Fatalf("CreateCertificates CA failed writing. Unable to continue: %s", err)
		}
		err = WriteCertPEM(caCertPEM, certFolder, CaCertFile)
	}

	// create the Server cert if needed
	serverCertPEM, _ := ReadPEM(certFolder, ServerCertFile)
	serverKeyPEM, _ := ReadPEM(certFolder, ServerKeyFile)
	if serverCertPEM == "" || serverKeyPEM == "" {
		serverKey := signing.CreateECDSAKeys()
		serverKeyPEM = signing.PrivateKeyToPem(serverKey)
		serverPubPEM, err := signing.PublicKeyToPem(&serverKey.PublicKey)
		if err != nil {
			logrus.Fatalf("CreateCertificateBundle server failed: %s", err)
		}
		serverCertPEM, err = CreateHubCert(hostname, serverPubPEM, caCertPEM, caKeyPEM)
		if err != nil {
			logrus.Fatalf("CreateCertificateBundle server failed: %s", err)
		}
		WriteKeyPEM(serverKeyPEM, certFolder, ServerKeyFile)
		WriteCertPEM(serverCertPEM, certFolder, ServerCertFile)
	}
	// create the Client cert if needed
	clientCertPEM, _ := ReadPEM(certFolder, ClientCertFile)
	clientKeyPEM, _ := ReadPEM(certFolder, ClientKeyFile)
	if clientCertPEM == "" || clientKeyPEM == "" {

		clientKey := signing.CreateECDSAKeys()
		clientKeyPEM = signing.PrivateKeyToPem(clientKey)
		clientPubKeyPEM, err := signing.PublicKeyToPem(&clientKey.PublicKey)
		if err != nil {
			logrus.Fatalf("CreateCertificateBundle client failed: %s", err)
		}
		clientCertPEM, err = CreateClientCert(hostname, api.OUPlugin, clientPubKeyPEM, caCertPEM, caKeyPEM)
		if err != nil {
			logrus.Fatalf("CreateCertificateBundle client failed: %s", err)
		}
		WriteKeyPEM(clientKeyPEM, certFolder, ClientKeyFile)
		WriteCertPEM(clientCertPEM, certFolder, ClientCertFile)
	}
	return nil
}

// CreateClientCert creates a client side Hub certificate for mutual authentication from client's public key
// The client role is intended to indicate authorization by role. It is stored in the
// certificate OrganizationalUnit. See RoleXxx in api
//
// This generates a certificate using the client's public key in PEM format
//  clientID used as the CommonName
//  ou of the client, stored as the OrganizationalUnit
//  clientPubKeyPEM with the client's public key
//  caCertPEM CA's certificate in PEM format.
//  caKeyPEM CA's ECDSA key used in signing.
// Returns the signed certificate or error
func CreateClientCert(clientID string, ou string, clientPubKeyPEM, caCertPEM string, caKeyPEM string) (certPEM string, err error) {
	var certDuration = DefaultCertDuration

	caPrivKey, err := signing.PrivateKeyFromPem(caKeyPEM)
	if err != nil {
		return "", err
	}
	caCert, err := CertFromPEM(caCertPEM)
	if err != nil {
		return "", err
	}

	clientPubKey := signing.PublicKeyFromPem(clientPubKeyPEM)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2021),
		Subject: pkix.Name{
			Organization:       []string{"WoST"},
			Locality:           []string{"WoST Zone"},
			CommonName:         clientID,
			OrganizationalUnit: []string{ou},
			Names:              make([]pkix.AttributeTypeAndValue, 0),
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Duration(certDuration)),

		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},

		IsCA:                  false,
		BasicConstraintsValid: true,
	}

	derCertBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, clientPubKey, caPrivKey)
	certPEM = CertDerToPEM(derCertBytes)
	return certPEM, err
}

// CreateHubCA creates WoST Hub Root CA certificate and private key for signing server certificates
// Source: https://shaneutt.com/blog/golang-ca-and-signed-cert-go/
// This creates a CA certificate used for signing client and server certificates.
// CA is valid for 'caDurationYears'
//
//  temporary set to generate a temporary CA for one-off signing
func CreateHubCA() (certPEM string, keyPEM string) {
	validity := caDefaultValidityDuration

	// set up our CA certificate
	// see also: https://superuser.com/questions/738612/openssl-ca-keyusage-extension
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2021),
		Subject: pkix.Name{
			Country:      []string{"CA"},
			Organization: []string{"WoST"},
			Province:     []string{"BC"},
			Locality:     []string{"WoST Zone"},
			CommonName:   "WoST CA",
		},
		NotBefore: time.Now().Add(-10 * time.Second),
		NotAfter:  time.Now().Add(validity),
		// CA cert can be used to sign certificate and revocation lists
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},

		// This hub cert is the only CA. Don't allow intermediate CAs
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create the CA private key
	privKey := signing.CreateECDSAKeys()
	privKeyPEM := signing.PrivateKeyToPem(privKey)

	// create the CA
	caCertDer, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &privKey.PublicKey, privKey)
	if err != nil {
		logrus.Errorf("CertSetup: Unable to create WoST Hub CA cert: %s", err)
		return "", ""
	}

	caCertPEM := CertDerToPEM(caCertDer)
	return caCertPEM, privKeyPEM
}

// CreateHubCert creates Wost server certificate
//  hosts contains one or more DNS or IP addresses to add tot he certificate. Localhost is always added
//  pubKey is the Hub public key in PEM format
//  caCertPEM is the CA to sign the server certificate
// returns the signed Hub certificate in PEM format
func CreateHubCert(hosts string, hubPublicKeyPEM string, caCertPEM string, caKeyPEM string) (certPEM string, err error) {
	// We need the CA key and certificate
	caPrivKey, err := signing.PrivateKeyFromPem(caKeyPEM)
	if err != nil {
		return "", err
	}
	caCert, err := CertFromPEM(caCertPEM)
	if err != nil {
		return "", err
	}

	hubPublicKey := signing.PublicKeyFromPem(hubPublicKeyPEM)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2021),
		Subject: pkix.Name{
			Organization: []string{"WoST"},
			Country:      []string{"CA"},
			Province:     []string{"BC"},
			Locality:     []string{"WoST Zone"},
			CommonName:   "WoST Hub",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Duration(DefaultCertDuration)),

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:           false,
		MaxPathLenZero: true,
		// BasicConstraintsValid: true,
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	// determine the hosts for this hub
	hostList := strings.Split(hosts, ",")
	for _, h := range hostList {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	certDer, err := x509.CreateCertificate(rand.Reader, template, caCert, hubPublicKey, caPrivKey)
	if err != nil {
		return "", err
	}
	certPEM = CertDerToPEM(certDer)

	return certPEM, nil
}

// Convert certificate DER encoding to PEM
//  derBytes is the output of x509.CreateCertificate
func CertDerToPEM(derCertBytes []byte) string {
	// pem encode certificate
	certPEMBuffer := new(bytes.Buffer)
	pem.Encode(certPEMBuffer, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derCertBytes,
	})
	return certPEMBuffer.String()
}

// Convert a PEM certificate to x509 instance
func CertFromPEM(certPEM string) (*x509.Certificate, error) {
	caCertBlock, _ := pem.Decode([]byte(certPEM))
	if caCertBlock == nil {
		return nil, errors.New("CertFromPEM pem.Decode failed")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	return caCert, err
}

// Read PEM file from certificate folder
// Return PEM file as string
func ReadPEM(certFolder string, fileName string) (pem string, err error) {
	pemPath := path.Join(certFolder, fileName)
	pemData, err := ioutil.ReadFile(pemPath)
	return string(pemData), err
}

// Write private key in pem format to file in the certificate folder
// permissions will be 0600
// Return error
func WriteKeyPEM(pem string, certFolder string, fileName string) error {
	pemPath := path.Join(certFolder, fileName)
	err := ioutil.WriteFile(pemPath, []byte(pem), 0600)
	return err
}

// Write certificate in pem format to file in the certificate folder
// permissions will be 0644
// Return error
func WriteCertPEM(pem string, certFolder string, fileName string) error {
	pemPath := path.Join(certFolder, fileName)
	err := ioutil.WriteFile(pemPath, []byte(pem), 0644)
	return err
}
