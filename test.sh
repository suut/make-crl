#!/usr/bin/env bash

if ! [[ -v VIRTUAL_ENV ]]; then
    echo 'run from a virtual environment' >&2
    exit 1
fi

TMPDIR=$(mktemp -d)

function cleanup () {
    rm -Rf "$TMPDIR"
}
trap cleanup EXIT

cd "$TMPDIR"

set -x

# Make a RSA CA certificate
openssl req -new -x509 -newkey RSA:2048 -noenc -keyout rsa-ca1.key -out rsa-ca1.pem -subj '/CN=RSA CA'

# Make another CA
openssl req -new -x509 -newkey EC -pkeyopt ec_paramgen_curve:P-384 -sha384 -noenc -keyout ecc-ca2.key -out ecc-ca2.pem -subj '/CN=RSA CA 2'

# Emit certificates signed by the first CA
openssl req -new -x509 -CA rsa-ca1.pem -CAkey rsa-ca1.key -newkey RSA:2048 -noenc -keyout leaf1-ca1.key -out leaf1-ca1.pem \
    -subj '/CN=Leaf 1 CA 1' -set_serial 0x01 -addext basicConstraints=critical,CA:FALSE
openssl req -new -x509 -CA rsa-ca1.pem -CAkey rsa-ca1.key -newkey RSA:2048 -noenc -keyout leaf2-ca1.key -out leaf2-ca1.pem \
    -subj '/CN=Leaf 2 CA 1' -set_serial 0x02 -addext basicConstraints=critical,CA:FALSE
openssl req -new -x509 -CA rsa-ca1.pem -CAkey rsa-ca1.key -newkey RSA:2048 -noenc -keyout leaf3-ca1.key -out leaf3-ca1.pem \
    -subj '/CN=Leaf 3 CA 1' -set_serial 0x03 -addext basicConstraints=critical,CA:FALSE

# Emit a certificate signed by the second CA
openssl req -new -x509 -CA ecc-ca2.pem -CAkey ecc-ca2.key -newkey EC -pkeyopt ec_paramgen_curve:P-384 -sha384 -noenc -keyout leaf1-ca2.key -out leaf1-ca2.pem \
    -subj '/CN=Leaf 1 CA 2' -set_serial 0x04 -addext basicConstraints=critical,CA:FALSE

echo '=== Make an empty CRL'
make-crl make-empty rsa-ca1.pem rsa-ca1.key rsa-ca1.crl || exit 1
openssl crl -noout -text < rsa-ca1.crl || exit 1

echo '=== Revoke the first certificate; with unspecified reason'
make-crl revoke --reason unspecified rsa-ca1.pem rsa-ca1.key rsa-ca1.crl leaf1-ca1.pem || exit 1
openssl crl -noout -text < rsa-ca1.crl || exit 1

echo '=== Revoke the second certificate, making an indirect CRL; with keyCompromise reason'
make-crl revoke --reason keyCompromise rsa-ca1.pem rsa-ca1.key rsa-ca1.crl leaf1-ca2.pem || exit 1
openssl crl -noout -text < rsa-ca1.crl || exit 1

echo '=== Revoke the third certificate, which should add the certificate issuer extension pointing to CA 1; with cessationOfOperation reason'
make-crl revoke --reason cessationOfOperation rsa-ca1.pem rsa-ca1.key rsa-ca1.crl leaf2-ca1.pem || exit 1
openssl crl -noout -text < rsa-ca1.crl || exit 1

echo '=== Revoke the fourth certificate, which should stop adding the certificate issuer extension now; with certificateHold reason'
make-crl revoke --reason certificateHold rsa-ca1.pem rsa-ca1.key rsa-ca1.crl leaf3-ca1.pem || exit 1
openssl crl -noout -text < rsa-ca1.crl || exit 1

echo '=== Check if the CRL is valid'
openssl crl -noout -verify -CAfile rsa-ca1.pem < rsa-ca1.crl || exit 1

echo '=== Try to revoke all certificates at the same time now; with reason keyCompromise'
rm rsa-ca1.crl
make-crl make-empty rsa-ca1.pem rsa-ca1.key rsa-ca1.crl || exit 1
openssl crl -noout -text < rsa-ca1.crl || exit 1
make-crl revoke --reason keyCompromise rsa-ca1.pem rsa-ca1.key rsa-ca1.crl leaf1-ca1.pem leaf1-ca2.pem leaf2-ca1.pem leaf3-ca1.pem || exit 1
openssl crl -noout -text < rsa-ca1.crl || exit 1

echo '=== Check if the CRL is valid'
openssl crl -noout -verify -CAfile rsa-ca1.pem < rsa-ca1.crl || exit 1

echo OK
exit 0
