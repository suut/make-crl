#!/usr/bin/env python3

import pyasn1.codec.der.encoder
import pyasn1.codec.der.decoder
import pyasn1.type.univ
import pyasn1.type.useful
import pyasn1.error

import pyasn1_modules.rfc5280

import subprocess
import sys
import argparse
import datetime
from pathlib import Path


def app():
    parser = argparse.ArgumentParser(description='Make an empty CRL from a certificate and a key')
    parser.add_argument('--digest', choices=('sha1', 'sha224', 'sha256', 'sha384', 'sha512'), default='sha256', help='Digest for signing the CRL (default %(default)s)')
    parser.add_argument('--provider', default=None, help='OpenSSL provider (default none)')
    parser.add_argument('--next-update', default=None, help='CRL nextUpdate, specify under the form YYMMDDhhmmss or +N where N is a number of days (default: when certificate expires)')
    parser.add_argument('certificate', help='The certificate file or PKCS#11 URI')
    parser.add_argument('key', help='The private key or PKCS#11 URI')
    parser.add_argument('outfile', help='The file in which to output the CRL')
    args = parser.parse_args()

    RSA_ENCRYPTION = pyasn1.type.univ.ObjectIdentifier('1.2.840.113549.1.1.1')
    RSA_SHA1_SIGNATURE = pyasn1.type.univ.ObjectIdentifier('1.2.840.113549.1.1.5')
    RSA_SHA224_SIGNATURE = pyasn1.type.univ.ObjectIdentifier('1.2.840.113549.1.1.14')
    RSA_SHA256_SIGNATURE = pyasn1.type.univ.ObjectIdentifier('1.2.840.113549.1.1.11')
    RSA_SHA384_SIGNATURE = pyasn1.type.univ.ObjectIdentifier('1.2.840.113549.1.1.12')
    RSA_SHA512_SIGNATURE = pyasn1.type.univ.ObjectIdentifier('1.2.840.113549.1.1.13')
    ELLIPTIC_CURVE = pyasn1.type.univ.ObjectIdentifier('1.2.840.10045.2.1')
    ECDSA_SHA1_SIGNATURE = pyasn1.type.univ.ObjectIdentifier('1.2.840.10045.4.1')
    ECDSA_SHA224_SIGNATURE = pyasn1.type.univ.ObjectIdentifier('1.2.840.10045.4.3.1')
    ECDSA_SHA256_SIGNATURE = pyasn1.type.univ.ObjectIdentifier('1.2.840.10045.4.3.2')
    ECDSA_SHA384_SIGNATURE = pyasn1.type.univ.ObjectIdentifier('1.2.840.10045.4.3.3')
    ECDSA_SHA512_SIGNATURE = pyasn1.type.univ.ObjectIdentifier('1.2.840.10045.4.3.4')

    if args.provider is not None:
        provider_args = ['-provider', 'default', '-provider', args.provider]
    else:
        provider_args = []

    try:
        out = subprocess.run(['openssl', 'x509', *provider_args, '-in', args.certificate, '-outform', 'DER'], check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        print('Error calling openssl to retrieve certificate:', file=sys.stderr)
        print(e.stderr.decode('utf-8'), file=sys.stderr, end='')
        sys.exit(1)

    signing_cert_bytes = out.stdout
    signing_cert, _ = pyasn1.codec.der.decoder.decode(signing_cert_bytes, asn1Spec=pyasn1_modules.rfc5280.Certificate())

    key_algo = signing_cert['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['algorithm']
    sig_algo = pyasn1_modules.rfc5280.AlgorithmIdentifier()
    if key_algo == RSA_ENCRYPTION:
        if args.digest == 'sha1':
            sig_algo['algorithm'] = RSA_SHA1_SIGNATURE
        elif args.digest == 'sha224':
            sig_algo['algorithm'] = RSA_SHA224_SIGNATURE
        elif args.digest == 'sha256':
            sig_algo['algorithm'] = RSA_SHA256_SIGNATURE
        elif args.digest == 'sha384':
            sig_algo['algorithm'] = RSA_SHA384_SIGNATURE
        elif args.digest == 'sha512':
            sig_algo['algorithm'] = RSA_SHA512_SIGNATURE
        sig_algo['parameters'] = pyasn1.codec.der.encoder.encode(pyasn1.type.univ.Null())
    elif key_algo == ELLIPTIC_CURVE:
        if args.digest == 'sha1':
            sig_algo['algorithm'] = ECDSA_SHA1_SIGNATURE
        if args.digest == 'sha224':
            sig_algo['algorithm'] = ECDSA_SHA224_SIGNATURE
        if args.digest == 'sha256':
            sig_algo['algorithm'] = ECDSA_SHA256_SIGNATURE
        if args.digest == 'sha384':
            sig_algo['algorithm'] = ECDSA_SHA384_SIGNATURE
        if args.digest == 'sha512':
            sig_algo['algorithm'] = ECDSA_SHA512_SIGNATURE
    else:
        sys.exit(f'Unsupported key algorithm {key_algo}')

    subject = signing_cert['tbsCertificate']['subject']

    if args.next_update is None:
        not_after = signing_cert['tbsCertificate']['validity']['notAfter']
    elif args.next_update.startswith('+'):
        not_after = pyasn1_modules.rfc5280.Time()
        try:
            not_after['utcTime'] = (datetime.datetime.now().astimezone(datetime.timezone.utc) + datetime.timedelta(days=int(args.next_update[1:]))).strftime('%y%m%d%H%M%SZ')
            pyasn1.codec.der.encoder.encode(not_after)  # test encoding
        except (ValueError, pyasn1.error.PyAsn1Error):
            sys.exit(f'Invalid number of days {args.next_update[1:]}')
    else:
        not_after = pyasn1_modules.rfc5280.Time()
        try:
            not_after['utcTime'] = pyasn1.type.useful.UTCTime(args.next_update + 'Z')
            pyasn1.codec.der.encoder.encode(not_after)  # test encoding
        except pyasn1.error.PyAsn1Error:
            sys.exit(f'Invalid date/time specifier {args.next_update}')

    not_before = pyasn1_modules.rfc5280.Time()
    not_before['utcTime'] = datetime.datetime.now().astimezone(datetime.timezone.utc).strftime('%y%m%d%H%M%SZ')

    cert_list = pyasn1_modules.rfc5280.TBSCertList()

    cert_list['version'] = 1
    cert_list['signature'] = sig_algo
    cert_list['issuer'] = subject
    cert_list['thisUpdate'] = not_before
    cert_list['nextUpdate'] = not_after

    to_be_signed_der = pyasn1.codec.der.encoder.encode(cert_list)

    try:
        out = subprocess.run(['openssl', 'pkeyutl', *provider_args, '-sign', '-inkey', args.key, '-rawin', '-digest', args.digest], check=True, input=to_be_signed_der, capture_output=True)
    except subprocess.CalledProcessError as e:
        print('Error calling openssl to sign CRL:', file=sys.stderr)
        print(e.stderr.decode('utf-8'), file=sys.stderr, end='')
        sys.exit(1)

    signature = out.stdout

    signed_cert_list = pyasn1_modules.rfc5280.CertificateList()

    signed_cert_list['tbsCertList'] = cert_list
    signed_cert_list['signatureAlgorithm'] = sig_algo
    signed_cert_list['signature'] = pyasn1.type.univ.BitString.fromOctetString(signature)

    Path(args.outfile).write_bytes(pyasn1.codec.der.encoder.encode(signed_cert_list))
