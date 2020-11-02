package gencert

import (
	"crypto/tls"
	"testing"
)

func TestMemoryCertMatch(t *testing.T) {
	_, err := tls.LoadX509KeyPair("testdata/memory/leaf.pem", "testdata/memory/leaf.key")
	if err != nil {
		t.Fatal(err)
	}
}

func TestFromDiskCertMatch(t *testing.T) {
	_, err := tls.LoadX509KeyPair("testdata/from-disk/leaf.pem", "testdata/from-disk/leaf.key")
	if err != nil {
		t.Fatal(err)
	}
}
