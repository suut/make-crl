CRL creation script
--------------

Script for creating CRLs signed by RSA or ECC (for ECDSA) certificates for micro-CA purposes, to replace the horrendous `openssl ca` command.

# Installation

Using `pipx` (`pip` will also work, but will complain if you are outside a virtual environment on certain distributions):

```sh
pipx install make-crl
```

The `openssl` commandline tool is required.

# Usage

## Quick reference

`--help` output:
```
usage: make-crl [-h] [--digest {sha1,sha224,sha256,sha384,sha512}] [--provider PROVIDER] [--next-update NEXT_UPDATE] SUBCOMMAND ...

Create and populate CRLs from a certificate and a key

options:
  -h, --help            show this help message and exit
  --digest {sha1,sha224,sha256,sha384,sha512}
                        Digest for signing the CRL (default sha256)
  --provider PROVIDER   OpenSSL provider (default none)
  --next-update NEXT_UPDATE
                        CRL nextUpdate, specify under the form YYMMDDhhmmss or +N where N is a number of days (default: when certificate expires)

subcommand:
  SUBCOMMAND            subcommand
    make-empty          Make the initial empty CRL
    revoke              Revoke a certificate
```

The generic arguments `--digest`, `--provider`, `--next-update` must come before the subcommand on the commandline.

`make-empty` subcommand:
```
usage: make-crl make-empty [-h] [-n CRL_NUMBER] certificate key outfile

positional arguments:
  certificate           The certificate file or PKCS#11 URI
  key                   The private key or PKCS#11 URI
  outfile               The file in which to output the CRL

options:
  -h, --help            show this help message and exit
  -n, --crl-number CRL_NUMBER
                        Initial CRL number (default 1)
```

`revoke` subcommand:
```
usage: make-crl revoke [-h]
                                  [-r {unspecified,keyCompromise,cACompromise,affiliationChanged,superseded,cessationOfOperation,certificateHold,privilegeWithdrawn,aACompromise}]
                                  certificate key crl to-revoke [to-revoke ...]

positional arguments:
  certificate           The certificate file or PKCS#11 URI
  key                   The private key or PKCS#11 URI
  crl                   The CRL file to update (the old file will be moved with a .old extension)
  to-revoke             The certificates to revoke

options:
  -h, --help            show this help message and exit
  -r, --reason {unspecified,keyCompromise,cACompromise,affiliationChanged,superseded,cessationOfOperation,certificateHold,privilegeWithdrawn,aACompromise}
                        Revocation reason (default unspecified)
```

## Creating an empty CRL with local certificates and keys

```sh
make-crl make-empty cert.pem key.pem output.crl
```

You will be prompted for the passphrase if necessary.

The CRL number of the created certificate will be `1`, but it can be changed with the `--crl-number` argument.

## Creating an empty CRL with keys stored in a smartcard or another PKCS#11 token

This requires installing `pkcs11-provider` as well as a suitable PKCS#11 module such as OpenSC from `opensc-pkcs11`
or the Yubico PKCS#11 module from `ykcs11`.


In this example the certificate is at `pkcs11:id=%45;type=cert` and the private key at `pkcs11:id=%45;type=private`,
and the PKCS#11 module is provided by OpenSC:

```sh
PROVIDER=$(find /usr/lib -path '*/ossl-modules/pkcs11.so' -print -quit)
export PKCS11_PROVIDER_MODULE=$(find /usr/lib -name 'opensc-pkcs11.so' -print -quit)
make-crl --provider "$PROVIDER" \
    make-empty \
    'pkcs11:id=%45;type=cert' \
    'pkcs11:id=%45;type=private' \
    output.crl
```

For a Yubikey you would do for instance:

```sh
PROVIDER=$(find /usr/lib -path '*/ossl-modules/pkcs11.so' -print -quit)
export PKCS11_PROVIDER_MODULE=$(find /usr/lib -name 'libykcs11.so' -print -quit)
make-crl --provider "$PROVIDER" \
    make-empty \
    'pkcs11:id=%02;object=X.509%20Certificate%20for%20Digital%20Signature;type=cert' \
    'pkcs11:id=%02;object=Private%20key%20for%20Digital%20Signature;type=private' \
    output.crl
```

You can also enable the PKCS#11 provider and corresponding module in `/etc/ssl/openssl.cnf` to skip having to give
the `--provider` argument and the `PKCS11_PROVIDER_MODULE` environment variable.

You will be prompted for the PIN code or the passphrase if necessary.

Use `pkcs11-tool -O -l --module "$PKCS11_PROVIDER_MODULE"` with the same `PKCS11_PROVIDER_MODULE` variable as defined above
in order to determine the PKCS#11 URI to use.

## Extra options

By default the `nextUpdate` field of the CRL is the same as the expiration date of the certificate.

You can give the `--next-update +N` argument to have it in `N` days from now, or give an exact time under the form
`--next-update YYMMDDhhmmss` in UTC time.

By default `sha256` is used, but you can give the values `sha1`, `sha224`, `sha256`, `sha384` or `sha512` to the `--digest` option.

With RSA >= 3072 or with P-384 or higher size curves you should probably use `sha384`.

## Revocating certificates

Revocating a certificate will update the CRL with the newly revoked certificate and increment the CRL number.

The previous CRL will be moved to the provided filename with a `.old-YYMMDDhhmmss` extension added, corresponding to the previous `thisUpdate` field.

This tool supports indirect CRLs which are signed with a certificate different from the one which issued the revoked certificate.
In this case you need to ensure that the `indirectCRL` boolean of the `issuingDistributionPoint` extension of the CA is set to true.

Usage with local keys and certificates, no revocation reason:

```sh
make-crl revoke ca.pem ca.key ca.crl certificate-to-revoke.pem
```

Usage with a PKCS#11 provider previously configured in `/etc/ssl/openssl.cnf`, with the `keyCompromise` reason:
```sh
make-crl revoke --reason=keyCompromise 'pkcs11:id=%45;type=cert' 'pkcs11:id=%45;type=private' ca.crl certificate-to-revoke-1.pem certificate-to-revoke-2.pem
```

Multiple certificates to revoke can be given, they will all be revoked with the same reason.
