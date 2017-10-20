import json
import base64
from OpenSSL import crypto
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import ctl_cert_parser_structure as ctls



def parse_ct_records(ct_entries):
    for ct_entry in ct_entries['entries']:

        leaf_input = ctls.MerkleTreeHeader.parse(base64.b64decode(ct_entry['leaf_input']))
        leaf_cert = ctls.Certificate.parse(leaf_input.Entry).CertData
        extra_data = ctls.CertificateChain.parse(base64.b64decode(ct_entry['extra_data']))
        # print("Converted leaft_input as Plaintext: \r \n")
        # print(leaf_input)
        # print("\r\n")
        # print("Converted extra_data as Plaintext: \r \n")
        # print(extra_data)
        #print("\r\n")
        print("-----Start-----------\r\n")
        parse_leaf_cert(leaf_cert)
        parse_chain_certs(extra_data)
        print("-----End-----------\r\n")

def parse_leaf_cert_crypto(leaf_cert):
    #print(leaf_cert)
    crypto_x509_cert = x509.load_der_x509_certificate(leaf_cert,default_backend())
    print(crypto_x509_cert.serial_number)
    print(crypto_x509_cert.public_key)

def parse_leaf_cert(leaf_cert):
    crypto_x509_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, leaf_cert)
    extensions = dump_extensions(crypto_x509_cert)
    print("Common Name: {}".format(crypto_x509_cert.get_subject().CN))
    print("Serial Number: {}".format(hex(crypto_x509_cert.get_serial_number())))
    print("Digest (sha256): {}".format(crypto_x509_cert.digest("sha256")))
    print("Issuer: {}".format(crypto_x509_cert.get_issuer().CN))

    #print(extensions)
    # print(crypto_x509_cert.digest("sha1"))
    # print(clean_san_dns_only(extensions['subjectAltName']))
    # print(extensions['keyUsage'])
    # print(crypto_x509_cert.get_pubkey().bits())
    # print(crypto.dump_publickey(crypto.FILETYPE_ASN1, crypto_x509_cert.get_pubkey()))
    # print(crypto_x509_cert.get_signature_algorithm())
    # print(crypto_x509_cert.get_version())
    # #print(extensions['extendedKeyUsage'])
    # asn1_time_to_UTC(crypto_x509_cert.get_notBefore())
    # asn1_time_to_UTC(crypto_x509_cert.get_notAfter())
    # print(crypto_x509_cert.has_expired())
    print("\r\n")

def parse_chain_certs(chain_certs):
    for intermediates in chain_certs.Chain:
        crypto_x509_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, intermediates.CertData)

        print("Common Name: {}".format(crypto_x509_cert.get_subject().CN))
        print("Serial Number: {}".format(hex(crypto_x509_cert.get_serial_number())))
        print("Digest (sha256): {}".format(crypto_x509_cert.digest("sha256")))
        print("Issuer: {}".format(crypto_x509_cert.get_issuer().CN))
        print("\r\n")

def dump_extensions(certificate):
    extensions = {}
    for x in range(certificate.get_extension_count()):
        extension_name = ""
        try:
            extension_name = certificate.get_extension(x).get_short_name()

            if extension_name == b'UNDEF':
                continue

            extensions[extension_name.decode('latin-1')] = certificate.get_extension(x).__str__()
        except:
            try:
                extensions[extension_name.decode('latin-1')] = "NULL"
            except Exception as e:
                pass
    return extensions

def clean_san_dns_only(san_extension):
    clean_sans = []
    if san_extension:
        for domain in san_extension.split(', '):
            if domain.startswith('DNS:'):
                clean_sans.append(domain.replace('DNS:', ''))

    return clean_sans

def asn1_time_to_UTC(asn1_time):
    return datetime.datetime.strptime(asn1_time.decode('ascii'),"%Y%m%d%H%M%SZ")

# Load Single Record
with open('single_record.json', encoding='utf-8') as data_file:
    single_record  = json.loads(data_file.read())

#Load Small Data Set

with open('small_set.json', encoding='utf-8') as data_file:
    small_set  = json.loads(data_file.read())

parse_ct_records(single_record)
parse_ct_records(small_set)
