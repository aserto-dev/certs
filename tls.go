package certs

import (
	"crypto/tls"
	"crypto/x509"
	"os"

	"github.com/pkg/errors"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
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

// ServerCredentials returns transport credentials for a GRPC server.
func (c *CertFiles) ServerCredentials() (credentials.TransportCredentials, error) {
	if c.NoTLS() {
		return insecure.NewCredentials(), nil
	}

	tlsConfig, err := c.ServerConfig()
	if err != nil {
		return nil, err
	}

	return credentials.NewTLS(tlsConfig), nil
}

// ClientCredentials returns transport credentials for a GRPC client.
func (c *CertFiles) ClientCredentials() (credentials.TransportCredentials, error) {
	if c.NoTLS() {
		return insecure.NewCredentials(), nil
	}

	tlsConfig, err := c.ClientConfig()
	if err != nil {
		return nil, err
	}

	return credentials.NewTLS(tlsConfig), nil
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

// GRPCServerTLSCreds gets TLS credentials for a GRPC server.
func GRPCServerTLSCreds(config CertFiles) (credentials.TransportCredentials, error) {
	certificate, err := tls.LoadX509KeyPair(config.Cert, config.Key)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load GRPC certs")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	}

	return credentials.NewTLS(tlsConfig), nil
}

// GatewayAsClientTLSCreds returns transport credentials so an HTTP gateway can connect to the GRPC server.
func GatewayAsClientTLSCreds(config CertFiles) (credentials.TransportCredentials, error) {
	certPool := x509.NewCertPool()

	caCertBytes, err := os.ReadFile(config.CA)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read ca cert: %s", config.CA)
	}

	ok := certPool.AppendCertsFromPEM(caCertBytes)
	if !ok {
		return nil, errors.Wrap(err, "failed to append client ca cert: %s")
	}

	certificate, err := tls.LoadX509KeyPair(config.Cert, config.Key)
	if err != nil {
		return nil, errors.Wrap(err, "could not load server key pair")
	}

	clientCreds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      certPool,
		MinVersion:   tls.VersionTLS12,
	})

	return clientCreds, nil
}

// GatewayServerTLSConfig returns a TLS config for the gateway server.
func GatewayServerTLSConfig(config CertFiles) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(config.Cert, config.Key)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load gateway certs")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	}

	return tlsConfig, nil
}
