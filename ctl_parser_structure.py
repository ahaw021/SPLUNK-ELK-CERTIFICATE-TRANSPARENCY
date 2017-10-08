from construct import Struct, Byte, Int16ub, Int64ub, Enum, Bytes, Int24ub, this, GreedyBytes, GreedyRange, Terminated, Embedded

MerkleTreeHeader = Struct(
    "Version"         / Byte,
    "MerkleLeafType"  / Byte,
    "Timestamp"       / Int64ub,
    "LogEntryType"    / Enum(Int16ub, X509LogEntryType=0, PrecertLogEntryType=1),
    "Entry"           / GreedyBytes
)

Certificate = Struct(
    "Length" / Int24ub,
    "CertData" / Bytes(this.Length)
)

CertificateChain = Struct(
    "ChainLength" / Int24ub,
    "Chain" / GreedyRange(Certificate),
)

PreCertEntry = Struct(
    "LeafCert" / Certificate,
    Embedded(CertificateChain),
    Terminated
)

def dump_cert(certificate):
    subject = certificate.get_subject()

    try:
        not_before = datetime.datetime.strptime(certificate.get_notBefore().decode('ascii'), "%Y%m%d%H%M%SZ").timestamp()
    except:
        not_before = 0

    try:
        not_after = datetime.datetime.strptime(certificate.get_notAfter().decode('ascii'), "%Y%m%d%H%M%SZ").timestamp()
    except:
        not_after = 0

    return {
        "subject": {
            "aggregated": repr(certificate.get_subject())[18:-2],
            "C": subject.C,
            "ST": subject.ST,
            "L": subject.L,
            "O": subject.O,
            "OU": subject.OU,
            "CN": subject.CN
        },
        "extensions": dump_extensions(certificate),
        "not_before": not_before,
        "not_after": not_after,
        "as_der": base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_ASN1, certificate)).decode('utf-8')
    }



def add_all_domains(cert_data):
    all_domains = []

    # Apparently we have certificates with null CNs....what?
    if cert_data['leaf_cert']['subject']['CN']:
        all_domains.append(cert_data['leaf_cert']['subject']['CN'])

    SAN = cert_data['leaf_cert']['extensions'].get('subjectAltName')

    if SAN:
        for entry in SAN.split(', '):
            if entry.startswith('DNS:'):
                all_domains.append(entry.replace('DNS:', ''))

    cert_data['leaf_cert']['all_domains'] = list(OrderedDict.fromkeys(all_domains))

    return cert_data
