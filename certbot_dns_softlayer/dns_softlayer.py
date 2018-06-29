"""DNS Authenticator for SoftLayer."""
import logging

import SoftLayer
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

from tld import get_tld
from SoftLayer.exceptions import SoftLayerAPIError

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for SoftLayer

    This Authenticator uses the SoftLayer API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certs using a DNS TXT record (if you are using SoftLayer for DNS).'

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the SoftLayer API.'

    def _setup_credentials(self):
        pass

    def _perform(self, domain, validation_name, validation):
        self._get_softlayer_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_softlayer_client().del_txt_record(domain, validation_name, validation)

    def _get_softlayer_client(self):
        return _SoftLayerClient()


class _SoftLayerClient(object):
    """
    Encapsulates all communication with the SoftLayer API.
    """

    def __init__(self):
        client = SoftLayer.create_client_from_env()
        self.dns = SoftLayer.DNSManager(client)

    def add_txt_record(self, domain_name, record_name, record_content):
        """
        Add a TXT record using the supplied information.

        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises certbot.errors.PluginError: if an error occurs communicating with the SoftLayer
                                            API
        """

        # extract first level domain
        domain = get_tld(domain_name, as_object=True, fix_protocol=True)

        try:
            zone_id = self.dns.resolve_ids(domain.fld)[0]
        except (SoftLayerAPIError, IndexError) as e:
            logger.debug('Error finding domain using the SoftLayer API: %s', e)
            raise errors.PluginError('Error finding domain using the SoftLayer API: {}'.format(e))

        try:
            logger.debug('Creating TXT record with name: %s', record_name)
            result = self.dns.create_record(zone_id, self._compute_record_name(domain.fld, record_name),
                                            'TXT', record_content)
            record_id = result['id']

            logger.debug('Successfully added TXT record with id: %d', record_id)
        except SoftLayerAPIError as e:
            logger.debug('Error adding TXT record using the SoftLayer API: %s', e)
            raise errors.PluginError('Error adding TXT record using the SoftLayer API: {0}'
                                     .format(e))

    def del_txt_record(self, domain_name, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.

        Failures are logged, but not raised.

        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """

        # extract first level domain
        domain = get_tld(domain_name, as_object=True, fix_protocol=True)

        try:
            zone_id = self.dns.resolve_ids(domain.fld)[0]
        except (SoftLayerAPIError, IndexError) as e:
            logger.debug('Error finding domain using the SoftLayer API: %s', e)
            return

        try:
            domain_records = self.dns.get_records(zone_id, host=self._compute_record_name(domain.fld, record_name),
                                                  data=record_content, record_type='TXT')
        except SoftLayer.Error as e:
            logger.debug('Error getting DNS records using the SoftLayer API: %s', e)
            return

        for record in domain_records:
            try:
                logger.debug('Removing TXT record with id: %s name: %s', record['id'], record['data'])
                self.dns.delete_record(record['id'])
            except SoftLayerAPIError as e:
                logger.warn('Error deleting TXT record %s using the SoftLayer API: %s',
                            record.id, e)

    @staticmethod
    def _compute_record_name(domain_name, full_record_name):
        # The domain, from SoftLayer's point of view, is automatically appended.
        return full_record_name.rpartition("." + domain_name)[0]
