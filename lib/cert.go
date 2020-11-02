package gencert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
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

type Config struct {
	// Which hosts to sign certificates for.
	Hosts []string
	// Which organization is issuing these certs, defaults to "Acme Co."
	Org string
	// How long leaf and client certs should be valid for, defaults to one year.
	LeafValidFor time.Duration
	// How long the root CA cert should be valid for, defaults to one year.
	RootValidFor time.Duration
	// Use root CA on disk to generate leaf certs, instead of generating a new
	// one. Should be a .key file with a root CA private key.
	RootCAPrivateKey string
	// Should be a .pem file with a root CA certificate. It is an error to set
	// RootCACert and not RootCAPrivateKey, or vice versa.
	RootCACert string
}

func Generate(cfg Config) (*Certs, error) {
	if cfg.RootCACert != "" && cfg.RootCAPrivateKey == "" {
		return nil, errors.New("gencert: must set both RootCACert and RootCAPrivateKey, or neither")
	}
	if cfg.RootCACert == "" && cfg.RootCAPrivateKey != "" {
		return nil, errors.New("gencert: must set both RootCACert and RootCAPrivateKey, or neither")
	}
	if cfg.RootCACert != "" && cfg.RootValidFor != 0 {
		return nil, errors.New("gencert: cannot set RootValidFor when loading root cert from disk")
	}
	if cfg.RootValidFor == 0 {
		cfg.RootValidFor = 365 * 24 * time.Hour
	}
	if cfg.LeafValidFor == 0 {
		cfg.LeafValidFor = 365 * 24 * time.Hour
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	notBefore := time.Now().UTC()
	leafNotAfter := notBefore.Add(cfg.LeafValidFor)

	leafSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}
	leafTemplate := x509.Certificate{
		IsCA:         false,
		SerialNumber: leafSerialNumber,
		Subject: pkix.Name{
			Organization: []string{cfg.Org},
			SerialNumber: leafSerialNumber.String(),
		},
		NotBefore: notBefore,
		NotAfter:  leafNotAfter,

		KeyUsage: x509.KeyUsageDigitalSignature,
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
			Organization: []string{cfg.Org},
			SerialNumber: clientSerialNumber.String(),
		},
		NotBefore: notBefore,
		NotAfter:  leafNotAfter,

		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
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

	var root *Cert
	var key *ecdsa.PrivateKey
	var rootTemplate *x509.Certificate
	if cfg.RootCAPrivateKey == "" {
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return nil, fmt.Errorf("failed to generate serial number: %s", err)
		}
		rootNotAfter := notBefore.Add(cfg.RootValidFor)
		rootTemplate = &x509.Certificate{
			IsCA:         true,
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Organization: []string{cfg.Org},
				SerialNumber: serialNumber.String(),
			},
			NotBefore: notBefore,
			NotAfter:  rootNotAfter,

			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			},
			BasicConstraintsValid: true,
		}

		root, key, err = genCert(rootTemplate, rootTemplate, nil)
		if err != nil {
			return nil, err
		}
	} else {
		certdata, err := ioutil.ReadFile(cfg.RootCACert)
		if err != nil {
			return nil, err
		}
		var certBlock *pem.Block
		certBlock, _ = pem.Decode(certdata)
		if certBlock == nil {
			return nil, fmt.Errorf("could not decode %q as PEM encoded CA certificate", cfg.RootCACert)
		}

		rootTemplate, err = x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, err
		}
		keydata, err := ioutil.ReadFile(cfg.RootCAPrivateKey)
		if err != nil {
			return nil, err
		}
		var keyBlock *pem.Block
		keyBlock, _ = pem.Decode(keydata)
		if keyBlock == nil {
			return nil, fmt.Errorf("could not decode %q as PEM encoded CA certificate", cfg.RootCAPrivateKey)
		}
		rawKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		key, ok = rawKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("could not parse private key as a *ecdsa.PrivateKey, use other parsing format")
		}
		root = &Cert{
			Private:      keyBlock,
			Public:       certBlock,
			PrivateBytes: keyBlock.Bytes,
			PublicBytes:  certBlock.Bytes,
		}
	}
	leaf, _, err := genCert(&leafTemplate, rootTemplate, key)
	if err != nil {
		return nil, err
	}
	client, _, err := genCert(&clientTemplate, rootTemplate, key)
	if err != nil {
		return nil, err
	}
	return &Certs{
		Root:   root,
		Leaf:   leaf,
		Client: client,
	}, nil
}

func genCert(leaf *x509.Certificate, parent *x509.Certificate, signingKey *ecdsa.PrivateKey) (*Cert, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if leaf == parent {
		if signingKey != nil {
			return nil, nil, fmt.Errorf("signing key must be nil when generating root cert")
		}
		signingKey = key
	}

	cert := new(Cert)
	derBytes, err := x509.CreateCertificate(rand.Reader, leaf, parent, &key.PublicKey, signingKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create certificate: %s", err)
	}
	cert.Public = &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, cert.Public); err != nil {
		return nil, nil, fmt.Errorf("failed to write data to cert.pem: %s", err)
	}
	cert.PublicBytes = make([]byte, buf.Len())
	copy(cert.PublicBytes, buf.Bytes())
	buf.Reset()

	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to marshal ECDSA private key: %v", err)
	}
	cert.Private = &pem.Block{Type: "PRIVATE KEY", Bytes: b}
	if err := pem.Encode(buf, cert.Private); err != nil {
		return nil, nil, fmt.Errorf("failed to encode key data: %s", err)
	}
	cert.PrivateBytes = make([]byte, buf.Len())
	copy(cert.PrivateBytes, buf.Bytes())
	return cert, key, nil
}
