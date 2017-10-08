import json
import base64
from OpenSSL import crypto

import ctl_parser_structure as ctls

def parse_ct_records(ct_entries):
    for ct_entry in ct_entries['entries']:

        ct_metadata = ctls.MerkleTreeHeader.parse(base64.b64decode(ct_entry['leaf_input']))
        leaf_cert = ctls.Certificate.parse(ct_metadata.Entry).CertData
        chain_certs = ctls.CertificateChain.parse(base64.b64decode(ct_entry['extra_data']))

        parse_chain_certs(chain_certs)
        parse_leaf_cert(leaf_cert)

def parse_leaf_cert(leaf_cert):

    crypto_x509_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, leaf_cert)
    extensions = dump_extensions(crypto_x509_cert)
    # print(crypto_x509_cert.get_serial_number())
    # print(crypto_x509_cert.get_issuer())
    # print(crypto_x509_cert.get_extension_count())
    #print(crypto_x509_cert.get_subject().CN)
    #print(extensions['subjectAltName'])
    #print(extensions['keyUsage'])
    #print(extensions['extendedKeyUsage'])
    print("\r\n")

def parse_chain_certs(chain_certs):
    for intermediates in chain_certs.Chain:
        crypto_x509_chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, intermediates.CertData)]
        # print("{}".format(intermediates.CertData))
        # print("{}".format(crypto_x509_chain[0].get_subject().CN))
        # print("{}".format(crypto_x509_chain[0].get_serial_number()))
        # print("{}".format(crypto_x509_chain[0].get_signature_algorithm()))
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

with open('./logs/1.test') as data_file:
    test1 = json.load(data_file)

with open('./logs/2.test') as data_file:
    test2 = json.load(data_file)

parse_ct_records(test1)
parse_ct_records(test2)
