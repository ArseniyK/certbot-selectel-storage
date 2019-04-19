"""Webroot Authenticator for Selectel Storage."""
import logging
import os

import zope.interface
from swiftclient.client import Connection

from acme import challenges
from certbot import interfaces
from certbot.plugins import common

logger = logging.getLogger(__name__)


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
        add("selectel-authurl", default='https://api.selcdn.ru/auth/v1.0',
            help="Selectel auth url")
        add("selectel-user", help="User name")
        add("selectel-key", help="Password")
        add("selectel-container", help="Container Name")

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
            self.conf('selectel-container'),
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
            authurl=self.conf('selectel-authurl'),
            user=self.conf('selectel-user'),
            key=self.conf('selectel-key'),
        )

    def cleanup(self, achalls):
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        for achall in achalls:
            conn = self.get_connection()
            conn.delete_object(self.conf('selectel-container'), achall.chall.path)
        return None