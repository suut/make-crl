#!/usr/bin/env python3

import pyasn1.codec.der.encoder
import pyasn1.codec.der.decoder
import pyasn1.type.univ

import pyasn1_modules.rfc5280

import subprocess
import sys
import argparse
from pathlib import Path


def app():
    parser = argparse.ArgumentParser(description='Make an empty CRL from a certificate and a key')
    parser.add_argument('certificate', help='The certificate file or PKCS#11 URI')
    parser.add_argument('key', help='The private key or PKCS#11 URI')
    parser.add_argument('outfile', help='The file in which to output the CRL')
    args = parser.parse_args()

    rsa_sha256_algo = pyasn1_modules.rfc5280.AlgorithmIdentifier()
    rsa_sha256_algo['algorithm'] = '1.2.840.113549.1.1.11'
    rsa_sha256_algo['parameters'] = b'\x05\x00'

    out = subprocess.run(['openssl', 'x509', '-in', args.certificate, '-outform', 'DER'], check=True, capture_output=True)
    signing_cert_bytes = out.stdout
    signing_cert, _ = pyasn1.codec.der.decoder.decode(signing_cert_bytes, asn1Spec=pyasn1_modules.rfc5280.Certificate())

    subject = signing_cert['tbsCertificate']['subject']
    not_before = signing_cert['tbsCertificate']['validity']['notBefore']
    not_after = signing_cert['tbsCertificate']['validity']['notAfter']

    cert_list = pyasn1_modules.rfc5280.TBSCertList()

    cert_list['version'] = 1
    cert_list['signature'] = rsa_sha256_algo
    cert_list['issuer'] = subject
    cert_list['thisUpdate'] = not_before
    cert_list['nextUpdate'] = not_after

    to_be_signed_der = pyasn1.codec.der.encoder.encode(cert_list)

    out = subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', args.key, '-rawin', '-digest', 'sha256'], check=True, input=to_be_signed_der, capture_output=True)
    signature = out.stdout

    signed_cert_list = pyasn1_modules.rfc5280.CertificateList()

    signed_cert_list['tbsCertList'] = cert_list
    signed_cert_list['signatureAlgorithm'] = rsa_sha256_algo
    signed_cert_list['signature'] = pyasn1.type.univ.BitString.fromOctetString(signature)

    Path(args.outfile).write_bytes(pyasn1.codec.der.encoder.encode(signed_cert_list))
