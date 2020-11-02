test:
	go test ./...

test-certs:
	go install -v ./...
	cd lib/testdata/memory && generate-cert --host memory.example.test
	cd lib/testdata/from-disk && generate-cert --host from-disk.example.test
	rm lib/testdata/from-disk/leaf*
	rm lib/testdata/from-disk/client*
	cd lib/testdata/from-disk && generate-cert --host from-disk.example.test \
		--root-ca-cert root.pem --root-ca-key root.key
