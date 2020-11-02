# generate-cert

This is designed to generate TLS root and leaf certificates. The problem with
the file in crypto/tls/generate_cert.go is that browsers do not like it when you
present a root CA certificate directly. Instead, we generate an intermediate
certificate and save that.

A previous iteration of this project was available from
github.com/Shyp/generate-tls-cert. I did not put a LICENSE file on that project
and I am not in a position to speak for the company anymore, so I am rewriting
it from scratch, without looking at that project. Any similarities are purely
coincidental. This project is released with an MIT license.

Note we exclusively generate and parse ecdsa keys, if you try to parse other
types of certificates the code will break.

## Testing

use `make test-certs` to regenerate the certs in `lib/testdata`, which are then
tested by code in `lib/cert_test.go`.

The certs will need to be regenerated when/if they expire.
