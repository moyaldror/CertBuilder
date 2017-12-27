import json
import os
from certs_maps import ENCODING_TYPES

CERTS_DEFAULTS_CONFIG_FILE = 'certs_defaults.cnf'

certs_defaults = {
    'subjName': {
        'CountryName': u'IL',
        'StateOrProvinceName': u'TLV',
        'OrganizationName': u'Radware',
        'OrganizationalUnitName': u'Appxcel',
        'CommonName': u'TestCert',
        'EmailAddress': u'drorm@radware.com',
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
root_ca_certs_defaults = {
    **certs_defaults,
    'subjName': {
        **certs_defaults['subjName'],
        'CommonName': u'TestRootCert',
    },
    'basicConstraints': {
        'ca': True,
        'path_length': None
    }
}
interm_certs_defaults = {
    **root_ca_certs_defaults,
    'subjName': {
        **certs_defaults['subjName'],
        'CommonName': u'TestIntermCert',
    },
}

default_cert_param_names = ['certs_defaults', 'root_ca_certs_defaults', 'interm_certs_defaults']
default_cert_params = [certs_defaults, root_ca_certs_defaults, interm_certs_defaults]
config = {name: obj for name, obj in zip(default_cert_param_names, default_cert_params)}


def write_cert_defaults_to_file():
    try:
        with open(CERTS_DEFAULTS_CONFIG_FILE, 'w') as defaults_file:
            json.dump({'config': config}, defaults_file, indent=2)
    except Exception as e:
        print("Failed to write default certificate parameters to file with error: {}".format(e))


def load_cert_defaults_from_file():
    try:
        with open(CERTS_DEFAULTS_CONFIG_FILE) as defaults_file:
            data = json.load(defaults_file)

        return data['config']

    except Exception as e:
        print("Failed to open default file with error: {}.{}"
              "Using hard coded default values".format(e, os.linesep))
        write_cert_defaults_to_file()
        return config


# decorator to set the class attributes
def set_certs_defaults(cls):
    defaults = load_cert_defaults_from_file()

    for defaults_name in default_cert_param_names:
        setattr(cls, defaults_name.upper(), defaults[defaults_name])

    return cls


@set_certs_defaults
class CertsDefaults(object):
    pass


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
