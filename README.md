CRL creation script
--------------

Script for creating empty CRLs signed by RSA or ECC (for ECDSA) certificates.

# Installation

Using `pipx` (`pip` will also work, but will complain if you are outside a virtual environment on certain distributions):

```sh
pipx install git+https://github.com/suut/make-crl.git
```

The `openssl` commandline tool is required.

# Usage

## With local certificates and keys

```sh
make-crl cert.pem key.pem output.crl
```

You will be prompted for the passphrase if necessary.

## With keys stored in a smartcard or another PKCS#11 token

This requires installing `pkcs11-provider` as well as a suitable PKCS#11 module such as OpenSC from `opensc-pkcs11`
or the Yubico PKCS#11 module from `ykcs11`.


In this example the certificate is at `pkcs11:id=%45;type=cert` and the private key at `pkcs11:id=%45;type=private`,
and the PKCS#11 module is provided by OpenSC:

```sh
PROVIDER=$(find /usr/lib -path '*/ossl-modules/pkcs11.so' -print -quit)
export PKCS11_PROVIDER_MODULE=$(find /usr/lib -name 'opensc-pkcs11.so' -print -quit)
make-crl --provider "$PROVIDER" \
    'pkcs11:id=%45;type=cert' \
    'pkcs11:id=%45;type=private' \
    output.crl
```

For a Yubikey you would do for instance:

```sh
PROVIDER=$(find /usr/lib -path '*/ossl-modules/pkcs11.so' -print -quit)
export PKCS11_PROVIDER_MODULE=$(find /usr/lib -name 'libykcs11.so' -print -quit)
make-crl --provider "$PROVIDER" \
    'pkcs11:id=%02;object=X.509%20Certificate%20for%20Digital%20Signature;type=cert' \
    'pkcs11:id=%02;object=Private%20key%20for%20Digital%20Signature;type=private' \
    output.crl
```

You can also enable the PKCS#11 provider and corresponding module in `/etc/ssl/openssl.cnf` to skip having to give
the `--provider` argument and the `PKCS11_PROVIDER_MODULE` environment variable.

You will be prompted for the PIN code or the passphrase if necessary.

Use `pkcs11-tool -O -l --module "$PKCS11_PROVIDER_MODULE"` with the same `PKCS11_PROVIDER_MODULE` variable as defined above
in order to determine the PKCS#11 URI to use.
