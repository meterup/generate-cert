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
