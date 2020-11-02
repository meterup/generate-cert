package main

import (
	"bufio"
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
	rootValidFor := flag.Duration("root-duration", 365*24*time.Hour, "Duration that root CA is valid for")
	organization := flag.String("organization", "Acme Co", "Company to issue the cert to")
	rootCAKey := flag.String("root-ca-key", "", "Use root CA on disk instead of generating one (should be a .key file)")
	rootCAPEM := flag.String("root-ca-cert", "", "Use root CA certificate on disk instead of generating one (should be a .pem file)")
	flag.Parse()
	if *version {
		fmt.Fprintf(os.Stderr, "generate-cert version %s\n", gencert.Version)
		os.Exit(0)
	}
	if *rootCAKey != "" && *rootCAPEM == "" {
		log.Fatal("must set both --root-ca-key and --root-ca-cert or neither")
	}
	if *rootCAKey == "" && *rootCAPEM != "" {
		log.Fatal("must set both --root-ca-key and --root-ca-cert or neither")
	}
	if *rootCAKey != "" && *rootValidFor == 365*24*time.Hour {
		// override default if you passed in a file, otherwise it will fail
		*rootValidFor = 0
	}

	hosts := strings.Split(*host, ",")
	certs, err := gencert.Generate(gencert.Config{
		Hosts:            hosts,
		Org:              *organization,
		RootValidFor:     *rootValidFor,
		LeafValidFor:     *validFor,
		RootCAPrivateKey: *rootCAKey,
		RootCACert:       *rootCAPEM,
	})
	if err != nil {
		log.Fatal(err)
	}

	w := bufio.NewWriter(os.Stdout)
	// only write root cert if we didn't just load it from disk
	if *rootCAKey == "" {
		if err := writeCert(certs.Root, "root"); err != nil {
			log.Fatal(err)
		}
	}
	if err := writeCert(certs.Leaf, "leaf"); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(w, `Wrote the following certs to disk - use these to terminate TLS traffic on a web server:

leaf.key - the private key
leaf.pem - the certificate

`)
	if err := writeCert(certs.Client, "client"); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(w, `Wrote the following certs to disk - use these to do client TLS (less common):

client.key - the private key
client.pem - the certificate
`)
	w.Flush()
}
