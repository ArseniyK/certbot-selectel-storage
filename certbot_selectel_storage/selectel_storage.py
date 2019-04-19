"""Webroot Authenticator for Selectel Storage."""
import logging
from urllib.parse import urljoin

import requests
import zope.interface
from acme import challenges
from swiftclient.client import Connection

from certbot import interfaces, errors
from certbot.plugins import common

logger = logging.getLogger(__name__)

UPLOAD_URL = 'https://api.selcdn.ru/v1/ssl/'
AUTH_URL = 'https://api.selcdn.ru/auth/v1.0'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(common.Plugin):
    """Webroot Authenticator for Selectel Storage

        This Authenticator uses the Selectel Storage API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a Webroot on selectel storage'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):
        add("user", help="User name")
        add("key", help="Password")
        add("container", help="Container Name")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return ('Authenticator plugin that performs http-01 challenge by saving '
                'necessary validation resources to Selectel Storage')

    def get_chall_pref(self, domain):  # pragma: no cover
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        return [challenges.HTTP01]

    def prepare(self):  # pylint: disable=missing-docstring,no-self-use
        pass  # pragma: no cover

    def perform(self, achalls):  # pylint: disable=missing-docstring
        responses = []
        for achall in achalls:
            responses.append(self._perform_single(achall))
        return responses

    def _perform_single(self, achall):
        """ Upload challenge file to container then run simple http verification
        """
        response, validation = achall.response_and_validation()
        conn = self.get_connection()

        conn.put_object(
            self.conf('container'),
            achall.chall.path,
            contents=validation,
            content_type='text/plain'
        )

        if response.simple_verify(
                achall.chall, achall.domain,
                achall.account_key.public_key(), self.config.http01_port):
            return response
        else:
            logger.error(
                "Self-verify of challenge failed")
            return None

    def get_connection(self):
        return Connection(
            auth_version='1',
            authurl=AUTH_URL,
            user=self.conf('user'),
            key=self.conf('key'),
        )

    def cleanup(self, achalls):
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        for achall in achalls:
            conn = self.get_connection()
            conn.delete_object(self.conf('container'), achall.chall.path)
        return None


@zope.interface.implementer(interfaces.IInstaller)
@zope.interface.provider(interfaces.IPluginFactory)
class Installer(common.Plugin):
    description = "Selectel storage Installer"

    @classmethod
    def add_parser_arguments(cls, add):
        add("user", help="User name")
        add("key", help="Password")

    def prepare(self):  # pylint: disable=missing-docstring,no-self-use
        pass  # pragma: no cover

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return ""

    def get_all_names(self):  # pylint: disable=missing-docstring,no-self-use
        pass  # pragma: no cover

    def get_connection(self):
        return Connection(
            auth_version='1',
            authurl=AUTH_URL,
            user=self.conf('user'),
            key=self.conf('key'),
        )

    def deploy_cert(self, domain, cert_path, key_path, chain_path, fullchain_path):
        url, token = self.get_connection().get_auth()
        name = '{0}_{1}.pem'.format(self.conf('user'), domain)
        fullchain = open(cert_path).read()
        key = open(key_path).read()
        body = ''.join([fullchain, key])
        self._deploy_cert(token, name, body)

    def _deploy_cert(self, token, name, body):
        url = urljoin(UPLOAD_URL, name)
        headers = {'X-Auth-Token': token}
        requests.delete(url, headers=headers)
        response = requests.put(url, headers=headers, data=body)
        if response.status_code != 200:
            raise errors.PluginError(response.text)

    def save(self, title=None, temporary=False):  # pylint: disable=no-self-use
        pass

    def enhance(self, domain, enhancement, options=None):  # pylint: disable=missing-docstring,no-self-use
        pass  # pragma: no cover

    def supported_enhancements(self):  # pylint: disable=missing-docstring,no-self-use
        return []  # pragma: no cover

    def get_all_certs_keys(self):  # pylint: disable=missing-docstring,no-self-use
        pass  # pragma: no cover

    def rollback_checkpoints(self, rollback=1):  # pylint: disable=missing-docstring,no-self-use
        pass  # pragma: no cover

    def recovery_routine(self):  # pylint: disable=missing-docstring,no-self-use
        pass  # pragma: no cover

    def view_config_changes(self):  # pylint: disable=missing-docstring,no-self-use
        pass  # pragma: no cover

    def config_test(self):  # pylint: disable=missing-docstring,no-self-use
        pass  # pragma: no cover

    def restart(self):  # pylint: disable=missing-docstring,no-self-use
        pass  # pragma: no cover

    def renew_deploy(self, lineage, *args, **kwargs): # pylint: disable=missing-docstring,no-self-use
        """
        Renew certificates when calling `certbot renew`
        """

        # Run deploy_cert with the lineage params
        self.deploy_cert(lineage.names()[0], lineage.cert_path, lineage.key_path, lineage.chain_path, lineage.fullchain_path)

        return


interfaces.RenewDeployer.register(Installer)
