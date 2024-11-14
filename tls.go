package certs

import (
	"crypto/tls"
	"crypto/x509"
	"os"

	"github.com/pkg/errors"
)

// CertFiles contains paths to an X509 certificate's key-pair and CA files.
type CertFiles struct {
	Cert string `json:"tls_cert_path"`
	Key  string `json:"tls_key_path"`
	CA   string `json:"tls_ca_cert_path"`
}

func (c *CertFiles) IsTLS() bool {
	return c != nil && c.Cert != "" && c.Key != "" && c.CA != ""
}

func (c *CertFiles) NoTLS() bool {
	return !c.IsTLS()
}

// ServerConfig returns TLS configuration for a server.
func (c *CertFiles) ServerConfig() (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if c.NoTLS() {
		return cfg, nil
	}

	certificate, err := tls.LoadX509KeyPair(c.Cert, c.Key)
	if err != nil {
		return cfg, errors.Wrapf(err, "failed to load gateway certs")
	}

	cfg.Certificates = []tls.Certificate{certificate}

	return cfg, nil
}

// ClientConfig returns TLS configuration for a client.
func (c *CertFiles) ClientConfig() (*tls.Config, error) {
	conf, err := c.ServerConfig()
	if err != nil {
		return &tls.Config{MinVersion: tls.VersionTLS12}, err
	}

	caCertBytes, err := os.ReadFile(c.CA)
	if err != nil {
		return conf, errors.Wrapf(err, "failed to read ca cert: %s", c.CA)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCertBytes) {
		return conf, errors.Wrap(err, "failed to append client ca cert: %s")
	}

	conf.RootCAs = certPool

	return conf, nil
}
