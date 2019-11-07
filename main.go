package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	gencert "github.com/meterup/generate-cert/lib"
)

func writeCert(c *gencert.Cert, rootFilename string) error {
	pubkey := rootFilename + ".pem"
	if err := ioutil.WriteFile(pubkey, c.PublicBytes, 0666); err != nil {
		return err
	}
	privkey := rootFilename + ".key"
	if err := ioutil.WriteFile(privkey, c.PrivateBytes, 0600); err != nil {
		return err
	}
	return nil
}

func main() {
	version := flag.Bool("version", false, "Print the version string and exit")
	host := flag.String("host", "", "Comma-separated hostnames and IPs to generate a certificate for")
	validFor := flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	organization := flag.String("organization", "Acme Co", "Company to issue the cert to")
	rootCert := flag.String("root-cert-path", "", "Path to a root certificate (will be generated if omitted)")
	rootKey := flag.String("root-key-path", "", "Path to a root key (will be generated if omitted)")
	clientCommonName := flag.String("client-common-name", "", "Common name for the client cert")
	flag.Parse()
	if *version {
		fmt.Fprintf(os.Stderr, "generate-cert version %s\n", gencert.Version)
		os.Exit(0)
	}

	hosts := strings.Split(*host, ",")
	cfg := gencert.Config{
		Hosts:            hosts,
		Org:              *organization,
		ValidFor:         *validFor,
		ClientCommonName: *clientCommonName,
	}

	var certs *gencert.Certs
	if *rootCert != "" {
		if *rootKey == "" {
			log.Fatal("root-cert-path and root-key-path must both be specified")
		}

		root, err := tls.LoadX509KeyPair(*rootCert, *rootKey)
		if err != nil {
			log.Fatalf("reading key pair: %s\n", err)
		}
		if root.Leaf == nil {
			root.Leaf, err = x509.ParseCertificate(root.Certificate[0])
			if err != nil {
				log.Fatalf("parsing x509 cert: %s\n", err)
			}
		}

		signer := root.PrivateKey.(crypto.Signer)

		certs, err = gencert.GenerateFromRoot(cfg, root.Leaf, signer)
		if err != nil {
			log.Fatalf("generating cert from root: %s", err)
		}
	} else {
		var err error
		certs, err = gencert.Generate(cfg)
		if err != nil {
			log.Fatalf("generating cert: %s", err)
		}

		if err := writeCert(certs.Root, "root"); err != nil {
			log.Fatal(err)
		}
	}

	if err := writeCert(certs.Leaf, "leaf"); err != nil {
		log.Fatal(err)
	}
	if err := writeCert(certs.Client, "client"); err != nil {
		log.Fatal(err)
	}
}
