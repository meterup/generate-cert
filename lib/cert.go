package gencert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"
)

const Version = "0.3"

type Cert struct {
	Private *pem.Block
	Public  *pem.Block

	PrivateBytes []byte
	PublicBytes  []byte
}

type Certs struct {
	Root, Leaf, Client *Cert
}

type Config struct {
	Hosts    []string
	Org      string
	ValidFor time.Duration

	ClientCommonName string
}

func Generate(cfg Config) (*Certs, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(cfg.ValidFor)

	rootTemplate := x509.Certificate{
		IsCA:         true,
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{cfg.Org},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	root, err := genCert(&rootTemplate, &rootTemplate, rootKey, rootKey)
	if err != nil {
		return nil, err
	}

	certs, err := GenerateFromRoot(cfg, &rootTemplate, rootKey)
	if err != nil {
		return nil, err
	}

	certs.Root = root
	return certs, nil
}

func GenerateFromRoot(cfg Config, rootTemplate *x509.Certificate, rootKey crypto.Signer) (*Certs, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	notBefore := time.Now()
	notAfter := notBefore.Add(cfg.ValidFor)

	leafSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}
	leafTemplate := x509.Certificate{
		IsCA:         false,
		SerialNumber: leafSerialNumber,
		Subject: pkix.Name{
			Organization: []string{cfg.Org},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	clientSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}
	clientTemplate := x509.Certificate{
		IsCA:         false,
		SerialNumber: clientSerialNumber,
		Subject: pkix.Name{
			CommonName:   cfg.ClientCommonName,
			Organization: []string{cfg.Org},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	for _, h := range cfg.Hosts {
		if ip := net.ParseIP(h); ip != nil {
			leafTemplate.IPAddresses = append(leafTemplate.IPAddresses, ip)
			clientTemplate.IPAddresses = append(clientTemplate.IPAddresses, ip)
		} else {
			leafTemplate.DNSNames = append(leafTemplate.DNSNames, h)
			clientTemplate.DNSNames = append(clientTemplate.DNSNames, h)
		}
	}

	leaf, err := genCert(&leafTemplate, rootTemplate, leafKey, rootKey)
	if err != nil {
		return nil, err
	}
	client, err := genCert(&clientTemplate, rootTemplate, clientKey, rootKey)
	if err != nil {
		return nil, err
	}
	return &Certs{
		Leaf:   leaf,
		Client: client,
	}, nil
}

func genCert(leaf *x509.Certificate, parent *x509.Certificate, key *ecdsa.PrivateKey, signer crypto.Signer) (*Cert, error) {
	cert := new(Cert)
	derBytes, err := x509.CreateCertificate(rand.Reader, leaf, parent, &key.PublicKey, signer)
	if err != nil {
		return nil, fmt.Errorf("Failed to create certificate: %s", err)
	}
	cert.Public = &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, cert.Public); err != nil {
		return nil, fmt.Errorf("failed to write data to cert.pem: %s", err)
	}
	cert.PublicBytes = make([]byte, buf.Len())
	copy(cert.PublicBytes, buf.Bytes())
	buf.Reset()

	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("Unable to marshal ECDSA private key: %v", err)
	}
	cert.Private = &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	if err := pem.Encode(buf, cert.Private); err != nil {
		return nil, fmt.Errorf("failed to encode key data: %s", err)
	}
	cert.PrivateBytes = make([]byte, buf.Len())
	copy(cert.PrivateBytes, buf.Bytes())
	return cert, nil
}
