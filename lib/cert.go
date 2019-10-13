package gencert

import (
	"bytes"
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

const Version = "0.2"

type Cert struct {
	Private *pem.Block
	Public  *pem.Block

	PrivateBytes []byte
	PublicBytes  []byte
}

type Certs struct {
	Root, Leaf, Client *Cert
}

func Generate(hosts []string, org string, validFor time.Duration) (*Certs, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)

	rootTemplate := x509.Certificate{
		IsCA:         true,
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
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

	leafSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}
	leafTemplate := x509.Certificate{
		IsCA:         false,
		SerialNumber: leafSerialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	clientSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}
	clientTemplate := x509.Certificate{
		IsCA:         false,
		SerialNumber: clientSerialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			leafTemplate.IPAddresses = append(leafTemplate.IPAddresses, ip)
			clientTemplate.IPAddresses = append(clientTemplate.IPAddresses, ip)
		} else {
			leafTemplate.DNSNames = append(leafTemplate.DNSNames, h)
			clientTemplate.DNSNames = append(clientTemplate.DNSNames, h)
		}
	}

	root, err := genCert(&rootTemplate, &rootTemplate)
	if err != nil {
		return nil, err
	}
	leaf, err := genCert(&leafTemplate, &rootTemplate)
	if err != nil {
		return nil, err
	}
	client, err := genCert(&clientTemplate, &rootTemplate)
	if err != nil {
		return nil, err
	}
	return &Certs{
		Root:   root,
		Leaf:   leaf,
		Client: client,
	}, nil
}

func genCert(leaf *x509.Certificate, parent *x509.Certificate) (*Cert, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	cert := new(Cert)
	derBytes, err := x509.CreateCertificate(rand.Reader, leaf, parent, &key.PublicKey, key)
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
