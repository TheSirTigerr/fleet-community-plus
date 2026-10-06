// Package enrollment implements the client-side SCEP enrollment flow used by Community+.
package enrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	scepserver "github.com/fleetdm/fleet/v4/server/mdm/scep/server"
	"github.com/smallstep/scep"
)

// Request contains the CSR and the temporary signing identity used for the SCEP exchange.
type Request struct {
	CSR        *x509.CertificateRequest
	SignerKey  *rsa.PrivateKey
	SignerCert *x509.Certificate
}

// RequestError represents a transport or protocol error for which retrying may succeed.
type RequestError struct {
	Err error
}

func (e RequestError) Error() string {
	if e.Err == nil {
		return "SCEP enrollment request failed"
	}
	return "SCEP enrollment request failed: " + e.Err.Error()
}

func (e RequestError) Unwrap() error { return e.Err }

// RejectedError represents a SCEP CertRep failure returned by the certificate authority.
type RejectedError struct {
	Status   scep.PKIStatus
	FailInfo scep.FailInfo
}

func (e RejectedError) Error() string {
	if e.FailInfo == "" {
		return fmt.Sprintf("SCEP enrollment rejected with status %s", e.Status)
	}
	return fmt.Sprintf("SCEP enrollment rejected with status %s (%s)", e.Status, e.FailInfo)
}

// NewEphemeralSigner creates a short-lived RSA identity used only to sign and decrypt
// the SCEP exchange. The requested certificate key remains the key from the caller's CSR.
func NewEphemeralSigner(subject pkix.Name) (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate SCEP signer key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generate SCEP signer serial: %w", err)
	}
	if subject.CommonName == "" {
		subject.CommonName = "Fleet SCEP enrollment"
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create SCEP signer certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse SCEP signer certificate: %w", err)
	}
	return key, cert, nil
}

// FetchCACerts retrieves the SCEP CA/RA certificates used to encrypt enrollment requests.
func FetchCACerts(ctx context.Context, client scepserver.Service) ([]*x509.Certificate, error) {
	if client == nil {
		return nil, errors.New("SCEP client is nil")
	}

	raw, count, err := client.GetCACert(ctx, "")
	if err != nil {
		return nil, RequestError{Err: err}
	}
	if len(raw) == 0 {
		return nil, errors.New("SCEP server returned an empty CA certificate response")
	}

	if count <= 1 {
		if cert, parseErr := x509.ParseCertificate(raw); parseErr == nil {
			return []*x509.Certificate{cert}, nil
		}
	}

	certs, err := scep.CACerts(raw)
	if err != nil {
		return nil, fmt.Errorf("parse SCEP CA certificates: %w", err)
	}
	if len(certs) == 0 {
		return nil, errors.New("SCEP server returned no CA certificates")
	}
	return certs, nil
}

// Enroll performs a PKCSReq exchange and returns the certificate issued for Request.CSR.
func Enroll(ctx context.Context, client scepserver.Service, caCerts []*x509.Certificate, req Request) (*x509.Certificate, error) {
	if client == nil {
		return nil, errors.New("SCEP client is nil")
	}
	if req.CSR == nil {
		return nil, errors.New("SCEP CSR is nil")
	}
	if req.SignerKey == nil || req.SignerCert == nil {
		return nil, errors.New("SCEP signer identity is incomplete")
	}
	if len(caCerts) == 0 {
		return nil, errors.New("SCEP CA certificates are empty")
	}

	request, err := scep.NewCSRRequest(req.CSR, &scep.PKIMessage{
		MessageType: scep.PKCSReq,
		Recipients:  caCerts,
		SignerCert:  req.SignerCert,
		SignerKey:   req.SignerKey,
	})
	if err != nil {
		return nil, fmt.Errorf("create SCEP PKCSReq: %w", err)
	}

	rawResponse, err := client.PKIOperation(ctx, request.Raw)
	if err != nil {
		return nil, RequestError{Err: err}
	}

	response, err := scep.ParsePKIMessage(rawResponse, scep.WithCACerts(caCerts))
	if err != nil {
		return nil, RequestError{Err: fmt.Errorf("parse SCEP CertRep: %w", err)}
	}
	if response.MessageType != scep.CertRep || response.CertRepMessage == nil {
		return nil, RequestError{Err: fmt.Errorf("unexpected SCEP response message type %s", response.MessageType)}
	}
	if response.TransactionID != request.TransactionID {
		return nil, RequestError{Err: errors.New("SCEP response transaction ID does not match request")}
	}
	if !bytes.Equal(response.CertRepMessage.RecipientNonce, request.SenderNonce) {
		return nil, RequestError{Err: errors.New("SCEP response recipient nonce does not match request")}
	}

	switch response.CertRepMessage.PKIStatus {
	case scep.FAILURE:
		return nil, RejectedError{
			Status:   response.CertRepMessage.PKIStatus,
			FailInfo: response.CertRepMessage.FailInfo,
		}
	case scep.PENDING:
		return nil, RequestError{Err: errors.New("SCEP enrollment is pending")}
	case scep.SUCCESS:
		if err := response.DecryptPKIEnvelope(req.SignerCert, req.SignerKey); err != nil {
			return nil, RequestError{Err: fmt.Errorf("decrypt SCEP CertRep: %w", err)}
		}
	default:
		return nil, RequestError{Err: fmt.Errorf("unexpected SCEP enrollment status %s", response.CertRepMessage.PKIStatus)}
	}

	cert := response.CertRepMessage.Certificate
	if cert == nil {
		return nil, RequestError{Err: errors.New("SCEP CertRep did not contain a certificate")}
	}

	csrPublicKey, err := x509.MarshalPKIXPublicKey(req.CSR.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal CSR public key: %w", err)
	}
	certPublicKey, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal issued certificate public key: %w", err)
	}
	if !bytes.Equal(csrPublicKey, certPublicKey) {
		return nil, errors.New("SCEP issued certificate public key does not match CSR")
	}

	return cert, nil
}
