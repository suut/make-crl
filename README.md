CRL creation script
--------------

Script for creating empty CRLs signed by RSA or ECC (for ECDSA) certificates.

# Installation

Using `pipx` (`pip` will also work, but will complain if you are outside a virtual environment on certain distributions):

```sh
pipx install git+https://github.com/suut/make-crl.git
```

# Usage

## With local certificates and keys

```sh
make-crl cert.pem key.pem output.crl
```

You will be prompted for the passphrase if necessary.

## With keys stored in a smartcard or another PKCS#11 token

This requires installing `pkcs11-provider` as well as a suitable PKCS#11 module such as OpenSC from `opensc-pkcs11`.

You must enable the PKCS#11 provider in `/etc/ssl/openssl.cnf` for this.

In this example the certificate is at `pkcs11:id=%45;type=cert` and the private key at `pkcs11:id=%45;type=private`:

```sh
make-crl 'pkcs11:id=%45;type=cert' 'pkcs11:id=%45;type=private' output.crl
```

You will be prompted for the PIN code or the passphrase if necessary.
