#!/usr/bin/env python3

import pyasn1.codec.der.encoder
import pyasn1.codec.der.decoder
import pyasn1.type.univ
import pyasn1.type.useful
import pyasn1.error

import pyasn1_modules.rfc5280

import hashlib
import subprocess
import sys
import argparse
import datetime
from pathlib import Path


def app():
    parser = argparse.ArgumentParser(description='Create and populate CRLs from a certificate and a key')
    parser.add_argument('--digest', choices=('sha1', 'sha224', 'sha256', 'sha384', 'sha512'), default='sha256', help='Digest for signing the CRL (default %(default)s)')
    parser.add_argument('--provider', default=None, help='OpenSSL provider (default none)')
    parser.add_argument('--next-update', default=None, help='CRL nextUpdate, specify under the form YYMMDDhhmmss or +N where N is a number of days (default: when certificate expires)')

    subparsers = parser.add_subparsers(title='subcommand', metavar='SUBCOMMAND', dest='subcommand', help='subcommand')
    make_empty_parser = subparsers.add_parser('make-empty', help='Make the initial empty CRL')
    revoke_parser = subparsers.add_parser('revoke', help='Revoke a certificate')

    make_empty_parser.add_argument('-n', '--crl-number', default=1, type=int, help='Initial CRL number (default %(default)s)')
    make_empty_parser.add_argument('certificate', help='The certificate file or PKCS#11 URI')
    make_empty_parser.add_argument('key', help='The private key or PKCS#11 URI')
    make_empty_parser.add_argument('outfile', help='The file in which to output the CRL')

    revoke_parser.add_argument('-r', '--reason', default='unspecified', choices=('unspecified', 'keyCompromise', 'cACompromise', 'affiliationChanged', 'superseded', 'cessationOfOperation', 'certificateHold', 'privilegeWithdrawn', 'aACompromise'), help='Revocation reason (default %(default)s)')
    revoke_parser.add_argument('certificate', help='The certificate file or PKCS#11 URI')
    revoke_parser.add_argument('key', help='The private key or PKCS#11 URI')
    revoke_parser.add_argument('crl', help='The CRL file to update (the old file will be moved with a .old extension)')
    revoke_parser.add_argument('to_revoke', metavar='to-revoke', nargs='+', help='The certificates to revoke')

    args = parser.parse_args()

    # OID definitions
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

    def retrieve_certificate(cert):
        try:
            out = subprocess.run(['openssl', 'x509', *provider_args, '-in', cert, '-outform', 'DER'], check=True, capture_output=True)
            return out.stdout
        except subprocess.CalledProcessError as e:
            print('Error calling openssl to retrieve certificate:', file=sys.stderr)
            print(e.stderr.decode('utf-8'), file=sys.stderr, end='')
            sys.exit(1)

    signing_cert_bytes = retrieve_certificate(args.certificate)
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
    key_identifier = hashlib.sha1(signing_cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'].asOctets()).digest()

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

    authority_key_identifier = pyasn1_modules.rfc5280.AuthorityKeyIdentifier()
    authority_key_identifier['keyIdentifier'] = key_identifier

    if args.subcommand == 'make-empty':
        cert_list = pyasn1_modules.rfc5280.TBSCertList()
        cert_list['version'] = 1
        cert_list['signature'] = sig_algo
        cert_list['issuer'] = subject
        cert_list['thisUpdate'] = not_before
        cert_list['nextUpdate'] = not_after
        cert_list['crlExtensions'][0]['extnID'] = pyasn1_modules.rfc5280.id_ce_authorityKeyIdentifier
        cert_list['crlExtensions'][0]['critical'] = True
        cert_list['crlExtensions'][0]['extnValue'] = pyasn1.codec.der.encoder.encode(authority_key_identifier)
        cert_list['crlExtensions'][1]['extnID'] = pyasn1_modules.rfc5280.id_ce_cRLNumber
        cert_list['crlExtensions'][1]['critical'] = True
        cert_list['crlExtensions'][1]['extnValue'] = pyasn1.codec.der.encoder.encode(pyasn1_modules.rfc5280.CRLNumber(args.crl_number))
    elif args.subcommand == 'revoke':
        previous_crl, _ = pyasn1.codec.der.decoder.decode(Path(args.crl).read_bytes(), asn1Spec=pyasn1_modules.rfc5280.CertificateList())
        cert_list = previous_crl['tbsCertList']
        if cert_list['version'] != 1:
            sys.exit('Expected CRL version 2')
        cert_list['signature'] = sig_algo
        if cert_list['issuer'] != subject:
            sys.exit('Input CRL is not signed by the same certificate')
        last_update = cert_list['thisUpdate']
        cert_list['thisUpdate'] = not_before
        cert_list['nextUpdate'] = not_after
        for i, ext in enumerate(cert_list['crlExtensions']):
            if ext['extnID'] == pyasn1_modules.rfc5280.id_ce_authorityKeyIdentifier:
                if ext['critical'] != True:
                    sys.exit('AKID extension is not marked as critical in input CRL')
                if ext['extnValue'] != pyasn1.codec.der.encoder.encode(authority_key_identifier):
                    sys.exit('Authority key identifier does not match certificate')
            elif ext['extnID'] == pyasn1_modules.rfc5280.id_ce_cRLNumber:
                if ext['critical'] != True:
                    sys.exit('CRL number extension is not marked as critical in input CRL')
                current_number, _ = pyasn1.codec.der.decoder.decode(ext['extnValue'], asn1Spec=pyasn1_modules.rfc5280.CRLNumber())
                cert_list['crlExtensions'][i]['extnValue'] = pyasn1.codec.der.encoder.encode(current_number + 1)
    else:
        sys.exit('Invalid subcommand')

    if args.subcommand == 'revoke':
        # Build the list of serial numbers that are already revoked so we do not make duplicates
        previously_revoked = set()
        last_was_indirect = False
        for cert in cert_list['revokedCertificates']:
            previously_revoked.add(int(cert['userCertificate']))
            last_was_indirect = False
            for ext in cert['crlEntryExtensions']:
                if ext['extnID'] == pyasn1_modules.rfc5280.id_ce_certificateIssuer:
                    dn, _ = pyasn1.codec.der.decoder.decode(ext['extnValue'], asn1Spec=pyasn1_modules.rfc5280.GeneralNames())
                    if dn[0]['directoryName'] != subject:
                        last_was_indirect = True

        # Add the certificates we want to revoke
        for cert_file in args.to_revoke:
            cert, _ = pyasn1.codec.der.decoder.decode(retrieve_certificate(cert_file), asn1Spec=pyasn1_modules.rfc5280.Certificate())
            if int(cert['tbsCertificate']['serialNumber']) in previously_revoked:
                print(f'Warning: {cert_file} is already revoked', file=sys.stderr)
                continue
            n = len(cert_list['revokedCertificates'])
            cert_list['revokedCertificates'][n]['userCertificate'] = cert['tbsCertificate']['serialNumber']
            cert_list['revokedCertificates'][n]['revocationDate'] = not_before
            # Check if the issuer is the same or if we need to add the certificate issuer extension (indirect CRL)
            if last_was_indirect or cert['tbsCertificate']['issuer'] != subject:
                dn = pyasn1_modules.rfc5280.GeneralNames()
                if cert['tbsCertificate']['issuer'] != subject:
                    print(f'Notice: {cert_file} is not issued by the current CA, treating it as indirect CRL', file=sys.stderr)
                    dn[0]['directoryName']['rdnSequence'] = cert['tbsCertificate']['issuer']['rdnSequence']
                else:
                    dn[0]['directoryName']['rdnSequence'] = subject['rdnSequence']

                issuer_extension = pyasn1_modules.rfc5280.Extension()
                issuer_extension['extnID'] = pyasn1_modules.rfc5280.id_ce_certificateIssuer
                issuer_extension['critical'] = True
                issuer_extension['extnValue'] = pyasn1.codec.der.encoder.encode(dn)
                cert_list['revokedCertificates'][n]['crlEntryExtensions'].append(issuer_extension)
                if last_was_indirect and cert['tbsCertificate']['issuer'] == subject:
                    # We stop adding the certificateIssuer extension as we are now adding certificates issued by the CA
                    last_was_indirect = False
                else:
                    last_was_indirect = True
            if args.reason != 'unspecified':
                reason_extension = pyasn1_modules.rfc5280.Extension()
                reason_extension['extnID'] = pyasn1_modules.rfc5280.id_ce_cRLReasons
                reason_extension['critical'] = False
                reason_extension['extnValue'] = pyasn1.codec.der.encoder.encode(pyasn1_modules.rfc5280.CRLReason(args.reason))
                cert_list['revokedCertificates'][n]['crlEntryExtensions'].append(reason_extension)
            previously_revoked.add(int(cert['tbsCertificate']['serialNumber']))

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

    if args.subcommand == 'make-empty':
        Path(args.outfile).write_bytes(pyasn1.codec.der.encoder.encode(signed_cert_list))
    else:
        outfile = Path(args.crl)
        outfile.rename(outfile.with_name(outfile.name + '.old-' + str(last_update['utcTime']).rstrip('Z')))
        outfile.write_bytes(pyasn1.codec.der.encoder.encode(signed_cert_list))
