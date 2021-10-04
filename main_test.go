package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func generateFakeServerCSR() (*x509.CertificateRequest, error) {
	// Generate a fake server private key
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Prepare a stub CSR
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:    []string{"ES"},
			CommonName: "ordr.inglaterra",
		},
		DNSNames: []string{"ordr.inglaterra", "google.com"},
	}

	// Embed the fake server public key in the CSR
	csrAsn, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, serverKey)
	if err != nil {
		return nil, err
	}

	// Rebuild the CSR object
	return x509.ParseCertificateRequest(csrAsn)
}

func generateFakeCertificateAuthority() (*CertificateAuthority, error) {
	// Generate a fake CA private key
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Generate a fake CA certificate
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "testing.ordr.fake"},
		NotBefore:             time.Now().Add(-10 * time.Minute).UTC(),
		NotAfter:              time.Now().Add(1 * time.Hour).UTC(),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	// Self-sign the CA
	certificateAsn, err := x509.CreateCertificate(rand.Reader, &template, &template, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	// Reload the Certificate structure, this time including signature
	certificate, err := x509.ParseCertificate(certificateAsn)
	if err != nil {
		return nil, err
	}

	return &CertificateAuthority{
		PrivateKey:  caKey,
		Certificate: certificate,
	}, nil
}

func TestHandleCertificateRequest(t *testing.T) {
	csr, err := generateFakeServerCSR()
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	ca, err := generateFakeCertificateAuthority()
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	result, err := handleCertificateRequest(csr, ca)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	asn1, err := base64toAsn1(result.Certificate, "CERTIFICATE")
	if err != nil {
		t.Errorf("%v", err)
	}

	cert, err := x509.ParseCertificate(asn1)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	if cert.Subject.CommonName != "ordr.inglaterra" {
		t.Error("SubjectName does not match expectation")
	}

	if cert.DNSNames[1] != "google.com" {
		t.Error("SAN DNS names do not pass expectations")
	}

	if cert.Issuer.CommonName != "testing.ordr.fake" {
		t.Error("Issuer does not match expectation")
	}
}
