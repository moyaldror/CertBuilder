from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import argparse
import sys
import os
import CertsBuilderConstants


def non_negative_int(value):
    try:
        int_val = int(value)
        if int_val < 0:
            raise argparse.ArgumentTypeError("Negative values are forbidden")

        return int_val
    except Exception as e:
        raise argparse.ArgumentTypeError(str(e))


class CertsArgParser:
    def __init__(self):
        self.parser = argparse.ArgumentParser(prog="CertsBuilder",
                                              epilog="Created By: Dror Moyal - Radware AX Group",
                                              description='A Human way to create certificates, keys, chains and more',
                                              formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        self.parser.add_argument('--version', action='version',
                                 version='%(prog)s {}, Written By: Dror Moyal 2017'
                                 .format(CertsBuilderConstants.VERSION))
        self.parser.add_argument('--certs_dir', default='certs' + os.sep, action='store', dest='path_to_create',
                                 help='Path to the put the certificates in')
        self.parser.add_argument('--depth', type=non_negative_int, default=0, action='store', dest='depth',
                                 help='Number of intermediate certificates to create for the chain')
        self.parser.add_argument('--certs', type=non_negative_int, default=1, action='store', dest='number_of_certs',
                                 help='Number of certificates to create')
        self.parser.add_argument('--export_chain', action='store_true', dest='export_chain',
                                 help='Export the chain of certs')
        self.parser.add_argument('--key_type', default='rsa', action='store', dest='key_type', choices=['rsa', 'ec'],
                                 help='Key type used to create the certificates')
        self.parser.add_argument('--days', default=365 * 10, type=int, action='store', dest='validity_days',
                                 help='Number of days the certificate will be valid for."'
                                      '"You can also use negative numbers')
        self.parser.add_argument('--key_size', default=2048, type=int, action='store', dest='key_size',
                                 choices=[512, 1024, 2048, 4096, 8192, 16384],
                                 help='Key size used for RSA keys')
        self.parser.add_argument('--hash_alg', default='SHA256', action='store', dest='hash_alg',
                                 choices=[name for name, cls in hashes.__dict__.items() if isinstance(cls, type) and
                                          issubclass(cls, hashes.HashAlgorithm) and cls is not hashes.HashAlgorithm],
                                 help='Hash algorithm used to sign the certificates')
        self.parser.add_argument('--ec_curve', default='SECP256R1', action='store', dest='ec_curve',
                                 choices=[name for name, cls in ec.__dict__.items() if isinstance(cls, type) and
                                          issubclass(cls, ec.EllipticCurve) and cls is not ec.EllipticCurve],
                                 help='EC curve to used for EC keys')
        self.parser.add_argument('--revoked', type=non_negative_int, default=0, action='store',
                                 dest='number_of_revoked_certs',
                                 help='Number of certificates to revoke out of the total created certs')
        self.parser.add_argument('--split_authorities', type=non_negative_int, default=1, action='store',
                                 dest='number_of_ca_branches',
                                 help='Number of Ca branches to create. Example: 2 will create 2 different branches of '
                                 'certificate authorities from the Root CA. This flag has no effect if --depth is 0')

    def parse_args(self, args=sys.argv[1:]):
        args = self.parser.parse_args(args)

        if not args.path_to_create.endswith(os.sep):
            args.path_to_create += os.sep

        if args.number_of_revoked_certs and args.number_of_revoked_certs > args.number_of_certs:
            print("Number of revoked certificates can't be larger than number of certificates")
            sys.exit(1)

        return args
