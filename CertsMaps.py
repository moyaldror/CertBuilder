from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def underscore_to_camel_case(word):
    return ''.join(x.capitalize() or '_' for x in word.split('_'))

HASH_ALG_MAP = {
    name: cls for name, cls in hashes.__dict__.items()
    if isinstance(cls, type) and issubclass(cls, hashes.HashAlgorithm) and cls is not hashes.HashAlgorithm
}
EC_CURVE_MAP = {
    name: cls for name, cls in ec.__dict__.items()
    if isinstance(cls, type) and issubclass(cls, ec.EllipticCurve) and cls is not ec.EllipticCurve
}


ATTR_TO_X509_OBJ = {
    'subjName': x509.Name,
    'altSubjName': x509.SubjectAlternativeName,
    'basicConstraints': x509.BasicConstraints,
}

ATTR_TO_X509_ATTR = {
    'name': x509.NameAttribute,
    'altDNS': x509.DNSName,
    'altIP': x509.IPAddress,
}

# This is a list of tuples because NameOID can't be a key in
# a dictionary
OID_TO_RN = [
    (NameOID.__dict__[oid], underscore_to_camel_case(oid)) for oid in NameOID.__dict__ if not oid.startswith('__')
]

ATTR_TO_OID = {
    name: oid for oid, name in OID_TO_RN
}

ENCODING_TYPES = {
    'DER': serialization.Encoding.DER,
    'PEM': serialization.Encoding.PEM
}

KEY_DEFAULTS = {
    'rsa': dict(
        type=rsa,
        params=dict(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
    ),
    'ec':  dict(
        type=ec,
        params=dict(
            curve=ec.SECP256R1,
            backend=default_backend()
        )
    )
}
