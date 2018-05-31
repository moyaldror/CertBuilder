from datetime import datetime
from datetime import timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from certs_maps import (OID_TO_RN, ATTR_TO_OID, ATTR_TO_X509_ATTR,
                        ATTR_TO_X509_OBJ, HASH_ALG_MAP, KEY_DEFAULTS)
from certs_utils import CertsDefaults, Decorators
import certs_builder_constants
import ipaddress
import math


class Cert:
    def __init__(self, key_params=KEY_DEFAULTS['rsa'], cert_params=CertsDefaults.CERTS_DEFAULTS, signing_cert=None):
        self._key = key_params['type'].generate_private_key(**key_params['params'])
        self._signing_key = self._key if signing_cert is None else signing_cert.key
        self.serial_number = x509.random_serial_number()
        self.file_name = "{}".format(cert_params['subjName']['CommonName'])
        self.basic_constraints = ATTR_TO_X509_OBJ['basicConstraints'](**cert_params['basicConstraints'])
        self.cert_extensions = self.basic_constraints
        self._not_before = datetime.utcnow()
        self._not_after = self._not_before
        self._cert = None
        self._hash = None

        self.alt_subj_name = ATTR_TO_X509_OBJ['altSubjName'](
            [ATTR_TO_X509_ATTR[alt_name.split('.')[0]]
                (cert_params['altSubjName'][alt_name]
                    if alt_name.split('.')[0] == 'altDNS'
                    else ipaddress.ip_address(cert_params['altSubjName'][alt_name]))
                for alt_name in cert_params['altSubjName'].keys()])

        self.subj_name = ATTR_TO_X509_OBJ['subjName'](
            [ATTR_TO_X509_ATTR['name'](ATTR_TO_OID[cert_attr], cert_params['subjName'][cert_attr])
                for cert_attr in cert_params['subjName'].keys()])

        self.issuer_name = self.subj_name if signing_cert is None else signing_cert.subj_name
        self._children = []
        self._parent = signing_cert
        if signing_cert:
            signing_cert.children.append(self)
            self._auth_key_id = x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_cert.key.public_key())
        else:
            self._auth_key_id = x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key())

        self._subj_key_id = x509.SubjectKeyIdentifier.from_public_key(self._key.public_key())

    @property
    def key(self):
        return self._key

    @property
    def hash(self):
        return self._hash

    @hash.setter
    def hash(self, hash_alg):
        self._hash = HASH_ALG_MAP[hash_alg]() if self._parent is None else self._parent.hash

    @property
    def not_before(self):
        return self._not_before.strftime(certs_builder_constants.OPENSSL_TIME_FORMAT)

    @property
    def not_after(self):
        return self._not_after.strftime(certs_builder_constants.OPENSSL_TIME_FORMAT)

    @property
    def validity_days(self):
        return self._not_after - self._not_before

    @validity_days.setter
    def validity_days(self, validity_days):
        self._not_before = (datetime.utcnow() if validity_days > 0
                            else datetime.utcnow() + timedelta(days=validity_days))
        self._not_after = self._not_before + timedelta(days=math.fabs(validity_days))

    @property
    def children(self):
        return self._children

    @property
    def parent(self):
        return self._parent

    def sign_certificate(self):
        self._cert = (
            x509.CertificateBuilder()
                .subject_name(self.subj_name)
                .issuer_name(self.issuer_name)
                .public_key(self._key.public_key())
                .serial_number(self.serial_number)
                .not_valid_before(self._not_before)
                .not_valid_after(self._not_after)
                .add_extension(self.basic_constraints, False)
                .add_extension(self.alt_subj_name, False)
                .add_extension(self._auth_key_id, False)
                .add_extension(self._subj_key_id, False)
                .sign(self._signing_key, self.hash, default_backend())
        )

    @Decorators.force_allowed_values_only(allowed_values=['PEM', 'DER'], keyword_name='encoding',
                                          error_msg='unsupported encoding')
    @Decorators.convert_encoding_type
    def get_cert(self, encoding='PEM'):
        return self._cert.public_bytes(encoding=encoding)

    @Decorators.force_allowed_values_only(allowed_values=['PEM', 'DER'], keyword_name='encoding',
                                          error_msg='unsupported encoding')
    @Decorators.convert_encoding_type
    def get_key(self, encoding='PEM'):
        return self._key.private_bytes(
            encoding=encoding,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def get_cert_and_key(self, encoding='PEM'):
        return self.get_cert(encoding=encoding) + self.get_key(encoding=encoding)

    def __str__(self):
        str_rep = []
        for comp in self.subj_name:
            for oid, oid_name in OID_TO_RN:
                if oid == comp.oid:
                    str_rep.append("/{}={}".format(oid_name, self.subj_name.get_attributes_for_oid(oid)[0].value))
                    break
        return "".join(str_rep)


class CaCert(Cert):
    def __init__(self, key_params=KEY_DEFAULTS['rsa'], cert_params=CertsDefaults.ROOT_CA_CERTS_DEFAULTS,
                 signing_cert=None, is_root=False):
        if is_root and signing_cert:
            raise ValueError("Root certificate is self signed. Passing a Signing Certificate is an error")
        self._is_root = is_root
        Cert.__init__(self, key_params=key_params, cert_params=cert_params, signing_cert=signing_cert)

    @property
    def is_root(self):
        return self._is_root


class RevokedCert:
    def __init__(self, revoked_cert=None, cert=None):
        if revoked_cert is None or cert is None:
            raise ValueError("RevokedCert constructor must get both x509 revoked certificate and a valid Cert object")
        self.revocation_date = revoked_cert.revocation_date.strftime(certs_builder_constants.OPENSSL_TIME_FORMAT)
        self.expiration_date = cert.not_after
        self.serial_number = cert.serial_number
        self.cert = cert
        self.revoked_cert = revoked_cert

    def __str__(self):
        return str(self.cert)


class CRL:
    def __init__(self, signing_cert=None):
        if signing_cert is None:
            raise ValueError("CRL Must have get a signing certificate")
        self._key = signing_cert.key
        self.signer_file_name = signing_cert.file_name
        self.file_name = "{}_CRL".format(signing_cert.subj_name)
        self.last_update = datetime.utcnow()
        self.next_update = self.last_update
        self._hash = signing_cert.hash
        self.issuer_name = signing_cert.subj_name
        self._builder = (x509.CertificateRevocationListBuilder()
                         .issuer_name(self.issuer_name))
        self._certs = {}
        self._crl = None

    @property
    def validity_days(self):
        return self.last_update - self.last_update

    @validity_days.setter
    def validity_days(self, validity_days):
        self.last_update = (datetime.utcnow() if validity_days > 0
                            else datetime.utcnow() + timedelta(days=validity_days))
        self.next_update = self.last_update + timedelta(days=math.fabs(validity_days))

    def add_certificate(self, cert):
        self._certs[cert.serial_number] = cert

    def revoke_certificate(self, serial_number):
        self._certs[serial_number] = RevokedCert(
            x509.RevokedCertificateBuilder().serial_number(serial_number)
                .revocation_date(datetime.utcnow()).build(default_backend()), self._certs[serial_number])
        self._builder = self._builder.add_revoked_certificate(self._certs[serial_number].revoked_cert)

    def sign_crl(self):
        self._builder = self._builder.last_update(self.last_update).next_update(self.next_update)
        self._crl = self._builder.sign(self._key, self._hash, default_backend())

    @Decorators.force_allowed_values_only(allowed_values=['PEM', 'DER'], keyword_name='encoding',
                                          error_msg='unsupported encoding')
    @Decorators.convert_encoding_type
    def get_crl(self, encoding='PEM'):
        return self._crl.public_bytes(encoding=encoding)

    def gen_index_file(self):
        """
        index.txt Generator function.
        Each iteration returns a certificate entry string for the index.txt file

        This is a generator because the index.txt can be huge
        index file should contains lines in the following format:
            [V/R] [expiration time] [revocation time] [serial] [cert file name] [subject name]
        """
        line_format = "{}\t{}\t{}\t{:X}\tunknown\t{}\n"
        for cert in self._certs.values():
            status, revocation_date, expiration_date = (
                ('R', cert.revocation_date, cert.expiration_date) if isinstance(cert, RevokedCert)
                else ('V', '', cert.not_after))
            yield line_format.format(status, expiration_date, revocation_date, cert.serial_number, str(cert))

    def get_ocsp_script(self, index_file_name="index.txt"):
        ocsp_str_format = "openssl ocsp  -index ./{0} -port {1} -text -rsigner ./{2} -rkey ./{2} -CA ./{2}"
        return ocsp_str_format.format(index_file_name, 9999, self.signer_file_name + ".crt")


class CertHelpers:
    indent_multiplier = 3

    @staticmethod
    def gen_cert_chain(cert):
        """
        Certificate Chain Generator function.
        Each iteration returns a certificate

        This is a generator because the chain can be massive
        """
        if cert.parent is not None:
            yield cert.get_cert(encoding='PEM').decode('UTF-8')
            for cert in CertHelpers.gen_cert_chain(cert.parent):
                yield cert
        else:
            yield cert.get_cert(encoding='PEM').decode('UTF-8')

    @staticmethod
    def get_cert_tree(cert, indent):
        tree_str = []
        if len(cert.children):
            tree_str.append("{}\n".format(cert.file_name) if type(cert) is CaCert and cert.is_root
                            else "|{}{}-> {}\n".format(" " * (indent - CertHelpers.indent_multiplier),
                                                       "-" * CertHelpers.indent_multiplier, cert.file_name))
            tree_str.append("|{}{}\n".format(" " * indent, '|' if indent != 0 else ''))
            for child_cert in cert.children:
                tree_str.append(CertHelpers.get_cert_tree(child_cert, indent+CertHelpers.indent_multiplier))
        else:
            tree_str.append("{}\n".format(cert.file_name) if type(cert) is CaCert and cert.is_root
                            else "|{}{}-> {}\n".format(" " * (indent - CertHelpers.indent_multiplier),
                                                       "-" * CertHelpers.indent_multiplier, cert.file_name))

        return "".join(tree_str)

