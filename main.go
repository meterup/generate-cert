package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

func genAndWriteCert(leaf *x509.Certificate, parent *x509.Certificate, fileroot string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, leaf, parent, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("Failed to create certificate: %s", err)
	}
	certOut, err := os.Create(fileroot + ".pem")
	if err != nil {
		return fmt.Errorf("failed to open %s.pem for writing: %s", fileroot, err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write data to cert.pem: %s", err)
	}
	if err := certOut.Close(); err != nil {
		return fmt.Errorf("error closing cert.pem: %s", err)
	}
	log.Printf("wrote %s.pem\n", fileroot)

	keyOut, err := os.OpenFile(fileroot+".key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("Unable to marshal ECDSA private key: %v", err)
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	if err := pem.Encode(keyOut, block); err != nil {
		log.Fatalf("failed to write data to key.pem: %s", err)
	}
	if err := keyOut.Close(); err != nil {
		return fmt.Errorf("error closing leaf.key: %s", err)
	}
	log.Printf("wrote %s.key\n", fileroot)
	return nil
}

func main() {
	host := flag.String("host", "", "Comma-separated hostnames and IPs to generate a certificate for")
	validFor := flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	organization := flag.String("organization", "Acme Co", "Company to issue the cert to")
	flag.Parse()

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(*validFor)

	rootTemplate := x509.Certificate{
		IsCA:         true,
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{*organization},
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
			Organization: []string{*organization},
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
			Organization: []string{*organization},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(*host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			leafTemplate.IPAddresses = append(leafTemplate.IPAddresses, ip)
			clientTemplate.IPAddresses = append(clientTemplate.IPAddresses, ip)
		} else {
			leafTemplate.DNSNames = append(leafTemplate.DNSNames, h)
			clientTemplate.DNSNames = append(clientTemplate.DNSNames, h)
		}
	}

	if err := genAndWriteCert(&rootTemplate, &rootTemplate, "root"); err != nil {
		log.Fatal(err)
	}
	if err := genAndWriteCert(&leafTemplate, &rootTemplate, "leaf"); err != nil {
		log.Fatal(err)
	}
	if err := genAndWriteCert(&clientTemplate, &rootTemplate, "client"); err != nil {
		log.Fatal(err)
	}
}
