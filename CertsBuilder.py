import copy
import pathlib
from CertsArgParser import CertsArgParser
from CertsBuilderObjects import Cert, CaCert, CRL, CertHelpers
from CertsMaps import EC_CURVE_MAP, KEY_DEFAULTS
from CertsUtils import CertsDefaults
import os
import sys


parser = CertsArgParser()
args = parser.parse_args()

# prepare key params
key_params = KEY_DEFAULTS[args.key_type]
if args.key_type is 'rsa':
    key_params['params']['key_size'] = args.key_size
else:
    key_params['params']['curve'] = EC_CURVE_MAP[args.ec_curve]

# prepare certs directory
try:
    pathlib.Path(args.path_to_create).mkdir(parents=True, exist_ok=False)
except FileExistsError as fe:
    print("Directory {}{}{} already exist, please remove it or change destination folder"
          .format(os.getcwd(), os.sep, args.path_to_create))
    sys.exit(1)


class FileUtils(object):
    @staticmethod
    def save_to_file(file_name="", data=None, file_ext=None, file_mode='w', permissions=0o777):
        if not file_name or not data or not file_ext:
            raise AttributeError("Parameter is missing")
        try:
            full_file_path = "{}.{}".format(args.path_to_create + file_name, file_ext)
            with open(full_file_path, file_mode) as f:
                f.write(data)
            os.chmod(full_file_path, permissions)
        except IOError:
            print("Could not write file:", file_name)
        except OSError:
            print("Os error", OSError)

    @staticmethod
    def rename_file(src_file_name="", dest_file_name=""):
        try:
            os.rename(src_file_name, dest_file_name)
        except OSError:
            try:
                os.replace(src_file_name, dest_file_name)
            except OSError:
                print("Failed to create file {}".format(dest_file_name))


def create_root_ca():
    print("Creating Root CA")

    ca = CaCert(key_params=key_params, is_root=True)
    ca.hash = args.hash_alg
    ca.validity_days = args.validity_days
    ca.sign_certificate()

    FileUtils.save_to_file(file_name=ca.file_name,
                           data=ca.get_cert_and_key(encoding='PEM').decode('UTF-8'), file_ext='crt')

    return ca


def create_interm_ca(cert_name_postfix="", signing_cert=None):
    print("Creating Intermediate CA #" + cert_name_postfix)

    inter_cert = CaCert(key_params=key_params, cert_params=params, signing_cert=signing_cert)
    inter_cert.hash = args.hash_alg
    inter_cert.validity_days = args.validity_days
    inter_cert.sign_certificate()

    FileUtils.save_to_file(file_name=inter_cert.file_name,
                           data=inter_cert.get_cert_and_key(encoding='PEM').decode('UTF-8'), file_ext='crt')

    return inter_cert


def create_cert(cert_name_postfix="", signing_cert=None):
    print("Creating Certificate #" + cert_name_postfix)

    cert = Cert(key_params=key_params, cert_params=params, signing_cert=signing_cert)
    cert.hash = args.hash_alg
    cert.validity_days = args.validity_days
    cert.sign_certificate()

    FileUtils.save_to_file(file_name=cert.file_name,
                           data=cert.get_cert_and_key(encoding='PEM').decode('UTF-8'), file_ext='crt')

    return cert


def revoke_certificates(parent_cert=None):
    serials_to_revoke = []

    for i in range(0, args.number_of_revoked_certs):
        server_certs = parent_cert.children
        print("Revoking Cert {}".format(server_certs[i].file_name))
        serials_to_revoke.append(server_certs[i].serial_number)
        full_file_path = args.path_to_create + server_certs[i].file_name
        FileUtils.rename_file(full_file_path + ".crt", full_file_path + "_revoked.crt")
        server_certs[i].file_name = server_certs[i].file_name + "_revoked"

    return serials_to_revoke


def create_crl(ca_branch_index=0, signing_cert=None, serials_to_revoke=None):
    print("Creating Crl #{} file".format(ca_branch_index))
    crl = CRL(signing_cert=signing_cert)
    crl.validity_days = args.validity_days

    for cert in server_certs:
        crl.add_certificate(cert)

    for serial in serials_to_revoke:
        crl.revoke_certificate(serial)

    crl.sign_crl()

    crl_name = "crl_{}".format(ca_branch_index) if end_interm_certs else "crl"

    FileUtils.save_to_file(file_name=crl_name,
                           data=crl.get_crl(encoding='PEM').decode('UTF-8'), file_ext='pem')

    return crl


def create_ocsp(ca_branch_index=0, crl=None):
    index_name = "index_{}".format(ca_branch_index) if end_interm_certs else "index"
    script_name = "run_ocsp_{}".format(ca_branch_index) if end_interm_certs else "run_ocsp"

    FileUtils.save_to_file(file_name=script_name,
                           data=crl.get_ocsp_script(index_file_name=index_name + '.txt'), file_ext='sh')
    for cert_line in crl.gen_index_file():
        FileUtils.save_to_file(file_name=index_name,
                               data=cert_line, file_ext='txt', file_mode='a+')


end_interm_certs = []
server_certs = []

ca_cert = create_root_ca()

for j in range(1, args.number_of_ca_branches + 1):
    # same root ca sign's all high level intermediates
    # noinspection PyRedeclaration
    signing_cert = ca_cert

    for i in range(1, args.depth + 1):
        params = copy.deepcopy(CertsDefaults.INTERM_CERTS_DEFAULTS)
        cert_name_postfix = "_{}".format(i) if args.number_of_ca_branches == 1 else "_{}_{}".format(j, i)
        params['subjName']['CommonName'] = params['subjName']['CommonName'] + cert_name_postfix
        inter_cert = create_interm_ca(cert_name_postfix=cert_name_postfix, signing_cert=signing_cert)

        # the intermediate that was just created will be used to sign the next leaf
        signing_cert = inter_cert

    if args.depth > 0 and inter_cert:
        end_interm_certs.append(inter_cert)

# if the depth is 0, the ca will sign all the end entities
if not args.depth:
    end_interm_certs.append(ca_cert)

# we will create args.number_of_certs for each ca branch
for j in range(1, len(end_interm_certs) + 1):
    signing_cert = end_interm_certs[j - 1]

    for i in range(1, args.number_of_certs + 1):
        params = copy.deepcopy(CertsDefaults.CERTS_DEFAULTS)
        cert_name_postfix = "_{}".format(i) if len(end_interm_certs) == 0 else "_{}_{}".format(j, i)
        params['subjName']['CommonName'] = params['subjName']['CommonName'] + cert_name_postfix

        # we save all end entities in the same list so that in case export_chain is on we will get the
        # chain from each certificate
        server_certs.append(create_cert(cert_name_postfix=cert_name_postfix, signing_cert=signing_cert))


if args.export_chain:
    # for each end entity we will call the chain generator that recursively
    # returns the chain, from end entity to the root
    for cert in server_certs:
        print("Creating Cert #{} chain file".format(cert.file_name))
        for cert_link in CertHelpers.gen_cert_chain(cert):
            FileUtils.save_to_file(file_name=cert.file_name + "_chain",
                                   data=cert_link, file_ext='crt', file_mode='a+')


if args.number_of_revoked_certs > 0:
    # if user choose to revoke certificates, by default we will also create CLR and OCSP
    # files
    for j in range(1, len(end_interm_certs) + 1):
        serials_to_revoke = []

        # we will use the intermediate to sign the crl
        signing_cert = end_interm_certs[j - 1]
        serials_to_revoke.append(*revoke_certificates(parent_cert=signing_cert))

        create_ocsp(ca_branch_index=j, crl=create_crl(ca_branch_index=j,
                                                      signing_cert=signing_cert, serials_to_revoke=serials_to_revoke))


# create ascii art representation of our CA store
FileUtils.save_to_file(file_name="cert_store_structure",
                       data=CertHelpers.get_cert_tree(ca_cert, 0), file_ext='txt')


print("\nDone!!!\n\nAll files can be found in {}".format(os.getcwd() + os.sep + args.path_to_create))

