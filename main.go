package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"time"

	runtime "github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

var smClient = secretsmanager.New(session.Must(session.NewSession()))
var caSecretName string = os.Getenv("CA_SM_SECRET_NAME")
var certificateDurationDays int = 90

type CertificateAuthority struct {
	PrivateKeyRaw  string `json:"privateKey"`
	CertificateRaw string `json:"certificate"`
	PrivateKey     *ecdsa.PrivateKey
	Certificate    *x509.Certificate
}

/**
 * Parses a base64 encoded PEM file.
 * Since PEM files can contain multiple blocks, a lookup is added to find a
 * specific block (eg: -----BEGIN CERTIFICATE REQUEST-----).
 *
 * Returns ASN.1 bytes.
 */
func base64toAsn1(b64 string, lookup string) ([]byte, error) {
	pemEncoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}

	for len(pemEncoded) > 0 {
		var block *pem.Block
		block, pemEncoded = pem.Decode(pemEncoded)
		if block != nil && block.Type == lookup {
			return block.Bytes, nil
		}
	}

	return nil, errors.New("could not find requested PEM block")
}

/**
 * Retrieves the Certificate Authority data from AWS Secrets manager.
 *
 * Returns a struct containing the PrivateKey and Certificate in both parsed
 * and raw forms.
 */
func getCertificateAuthority() (*CertificateAuthority, error) {
	result := &CertificateAuthority{}

	input := &secretsmanager.GetSecretValueInput{
		SecretId: &caSecretName,
	}

	// Retrieve the secret
	resp, err := smClient.GetSecretValue(input)
	if err != nil {
		return result, err
	}

	// Parse the JSON data
	err = json.Unmarshal([]byte(*resp.SecretString), &result)
	if err != nil {
		return result, err
	}

	// Decode base64 pem key file to ASN.1
	privateKeyRaw, err := base64toAsn1(result.PrivateKeyRaw, "EC PRIVATE KEY")
	if err != nil {
		return result, err
	}

	// Decode base64 pem certificate to ASN.1
	certificateRaw, err := base64toAsn1(result.CertificateRaw, "CERTIFICATE")
	if err != nil {
		return result, err
	}

	// Build an EC Key object
	result.PrivateKey, err = x509.ParseECPrivateKey(privateKeyRaw)
	if err != nil {
		return result, err
	}

	// Build a x509 Certificate object
	result.Certificate, err = x509.ParseCertificate(certificateRaw)
	if err != nil {
		return result, err
	}

	return result, nil
}

/**
 * Builds an unsigned Certificate file using the Certificate Request fields.
 */
func csrToCrt(csr *x509.CertificateRequest) *x509.Certificate {
	serial, err := rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), nil))
	if err != nil {
		return nil
	}

	certificate := x509.Certificate{
		SerialNumber:   serial,
		Subject:        csr.Subject,
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(0, 0, certificateDurationDays),
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageContentCommitment |
			x509.KeyUsageDataEncipherment |
			x509.KeyUsageKeyEncipherment,
	}

	// This sets SAN fields. While the CSR should provide the required SANs,
	// doing so is annoyingly complicated. Assuming most will not set the SAN
	// fields, we can fall back to using the Subject CommonName.
	// This is because most modern browsers require the SAN fields to be set.
	if len(certificate.DNSNames) == 0 {
		certificate.DNSNames = []string{certificate.Subject.CommonName}
	}

	return &certificate
}

type CertificateRequestResponse struct {
	CA          string `json:"ca"`
	Certificate string `json:"certificate"`
	Error       string `json:"error"`
}

/**
 * Generates and signs a Certificate for the specified CSR using the secret CA
 */
func handleCertificateRequest(csr *x509.CertificateRequest, ca *CertificateAuthority) (*CertificateRequestResponse, error) {
	// Build a Certificate from the Certificate Request
	crtTemplate := csrToCrt(csr)
	if crtTemplate == nil {
		return nil, errors.New("could not generate Certificate template")
	}

	// Sign the Certificate using the CA key
	certificate, err := x509.CreateCertificate(
		rand.Reader,
		crtTemplate,
		ca.Certificate,
		csr.PublicKey,
		ca.PrivateKey,
	)
	if err != nil {
		fmt.Printf("HI %v", csr.PublicKey)
		return nil, err
	}

	// Encode the result to PEM
	var result bytes.Buffer
	err = pem.Encode(&result, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	if err != nil {
		return nil, err
	}

	return &CertificateRequestResponse{
		Certificate: base64.StdEncoding.EncodeToString(result.Bytes()),
		CA:          ca.CertificateRaw,
	}, nil
}

type EventData struct {
	CSR string `json:"csr"`
}

/**
 * Lambda function entry point.
 * - Parses the request body
 * - Retrieves the AWS SM CA secret
 * - Invokes the actual job handler
 * - Encodes the success/error response to json
 */
func HandleRequest(_ context.Context, event EventData) (CertificateRequestResponse, error) {
	// Parse the CSR to ASN.1
	csrRaw, err := base64toAsn1(event.CSR, "CERTIFICATE REQUEST")
	if err != nil {
		return CertificateRequestResponse{Error: err.Error()}, err
	}

	// Build a CSR object
	csr, err := x509.ParseCertificateRequest(csrRaw)
	if err != nil {
		return CertificateRequestResponse{Error: err.Error()}, err
	}

	// Retrieve the CA
	certificateAuthority, err := getCertificateAuthority()
	if err != nil {
		return CertificateRequestResponse{Error: err.Error()}, err
	}

	// Do the thingy...
	response, err := handleCertificateRequest(csr, certificateAuthority)
	if err != nil {
		return CertificateRequestResponse{Error: err.Error()}, err
	}

	return *response, nil
}

func main() {
	// Allow for configuration of the certificate duration
	if os.Getenv("CERTIFICATE_DURATION_DAYS") != "" {
		v, err := strconv.Atoi(os.Getenv("CERTIFICATE_DURATION_DAYS"))
		if err == nil {
			certificateDurationDays = v
		}
	}

	runtime.Start(HandleRequest)
}
