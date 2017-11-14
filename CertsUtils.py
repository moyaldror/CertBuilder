import json
import os
from CertsMaps import ENCODING_TYPES

CERTS_DEFAULTS_CONFIG_FILE = 'certs_defaults.cnf'
CERTS_DEFAULTS = 'cert_defaults', 0
ROOT_CA_CERTS_DEFAULTS = 'root_ca_cert_defaults', 1
INTERMEDIATE_CA_CERTS_DEFAULTS = 'interm_ca_cert_defaults', 2

cert_defaults = {
    'subjName': {
        'Country': u'IL',
        'State': u'TLV',
        'Organization': u'Radware',
        'OrganizationUnit': u'Appxcel',
        'CommonName': u'TestCert',
        'E-Mail': u'drorm@radware.com',
    },
    'altSubjName': {
        'altDNS.0': u'alt.Test',
        'altIP.0': u'0.0.0.0',
    },
    'basicConstraints': {
        'ca': False,
        'path_length': None
    }
}

root_ca_cert_defaults = {
    **cert_defaults,
    'subjName': {
        **cert_defaults['subjName'],
        'CommonName': u'TestRootCert',
    },
    'basicConstraints': {
        'ca': True,
        'path_length': 0
    }
}

interm_cert_defaults = {
    **root_ca_cert_defaults,
    'subjName': {
        **cert_defaults['subjName'],
        'CommonName': u'TestIntermCert',
    },
}


def write_cert_defaults_to_file():
    try:
        with open(CERTS_DEFAULTS_CONFIG_FILE, 'w') as defaults_file:
            json.dump(
                {
                    'config': [
                        {CERTS_DEFAULTS[0]: cert_defaults},
                        {ROOT_CA_CERTS_DEFAULTS[0]: root_ca_cert_defaults},
                        {INTERMEDIATE_CA_CERTS_DEFAULTS[0]: interm_cert_defaults}
                    ]
                }, defaults_file, indent=2)
    except Exception as e:
        print("Failed to write default certificate parameters to file with error: {}".format(e))


def load_cert_defaults_from_file():
    try:
        with open(CERTS_DEFAULTS_CONFIG_FILE) as defaults_file:
            data = json.load(defaults_file)

        return {
            CERTS_DEFAULTS[0]:
                data['config'][CERTS_DEFAULTS[1]][CERTS_DEFAULTS[0]],
            ROOT_CA_CERTS_DEFAULTS[0]:
                data['config'][ROOT_CA_CERTS_DEFAULTS[1]][ROOT_CA_CERTS_DEFAULTS[0]],
            INTERMEDIATE_CA_CERTS_DEFAULTS[0]:
                data['config'][INTERMEDIATE_CA_CERTS_DEFAULTS[1]][INTERMEDIATE_CA_CERTS_DEFAULTS[0]],
        }
    except Exception as e:
        print("Failed to open default file with error: {}.{}"
              "Using hard coded default values".format(e, os.linesep))
        write_cert_defaults_to_file()
        return {
            CERTS_DEFAULTS[0]: cert_defaults,
            ROOT_CA_CERTS_DEFAULTS[0]: root_ca_cert_defaults,
            INTERMEDIATE_CA_CERTS_DEFAULTS[0]: interm_cert_defaults,
        }


class CertsDefaults(object):
    defaults = load_cert_defaults_from_file()
    CERTS_DEFAULTS = defaults[CERTS_DEFAULTS[0]]
    ROOT_CA_CERTS_DEFAULTS = defaults[ROOT_CA_CERTS_DEFAULTS[0]]
    INTERMEDIATE_CA_CERTS_DEFAULTS = defaults[INTERMEDIATE_CA_CERTS_DEFAULTS[0]]


class Decorators(object):
    @staticmethod
    def force_allowed_values_only(allowed_values=None, keyword_name="", error_msg=""):
        """
        :param allowed_values: iterable containing all allowed values
        :param keyword_name: the keyword parameter name we want to check
        :param error_msg: error message to display in case the value is not in the allowed values
        :return: a decorator function to enforce the allowed values on the give keyword parameter
        """

        # noinspection PyUnusedLocal
        allowed_values_iterator = iter(allowed_values)
        # allowed_values must me iterable, otherwise raise exception

        def decorator(func):
            def decorated(*args, **kwargs):
                if kwargs[keyword_name] not in allowed_values:
                    raise ValueError("{} ({})".format(error_msg, kwargs[keyword_name]))
                return func(*args, **kwargs)
            return decorated
        return decorator

    @staticmethod
    def convert_encoding_type(func):
        """
        Decorator to ease the use of encoding type

        :param func: function to decorate
        :return: a decorated function
        """

        def decorated(*args, **kwargs):
            kwargs = {**kwargs, 'encoding': ENCODING_TYPES[kwargs['encoding']]}
            return func(*args, **kwargs)

        return decorated
