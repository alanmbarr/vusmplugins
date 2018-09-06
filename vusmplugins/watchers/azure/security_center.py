"""
.. module: vusmplugins.watchers.security_center
    :platform: Unix
    :synopsis: Watcher for Azure Security Center.


.. version:: $$VERSION$$
.. moduleauthor:: Alan Barr <alan.barr@vu.com>

"""
from security_monkey import app
from vusmplugins.util import get_azure_creds, iter_accounts, azure_cli_general_command, azure_cli_login_with_service_principal
from security_monkey.datastore import Account
from security_monkey.decorators import record_exception
from vusmplugins.exceptions import InvalidResponseCodeFromAzureError
from security_monkey.watcher import Watcher, ChangeItem
import requests
import json

AZURE_URL = "https://management.azure.com/subscriptions/"

class AzureSecurityCenter(Watcher):
    index = 'security_center'
    i_am_singular = 'security_center'
    i_am_plural = 'security_center'
    account_type = 'Azure'

    def __init__(self, accounts=None, debug=False):
        super(AzureSecurityCenter, self).__init__(accounts=accounts, debug=debug)
        self.azure_creds = get_azure_creds(self.accounts)

    def slurp(self):
        @record_exception(source="{index}-watcher".format(index=self.index))
        def fetch_security_details(**kwargs):
            item_list = []
            account = Account.query.filter(Account.name == kwargs["account_name"]).first()

            # Fetch the initial Azure Security Center details:
            app.logger.debug("Fetching initial org details for: {}".format(account.identifier))
            security_details = self.get_security_details(account.identifier)

            item_list.append(AzureSecurityCenterItem(
                account=account.name,
                name=account.identifier,
                arn=account.identifier,
                config=security_details,
                source_watcher=self
            ))

            return item_list, kwargs["exception_map"]

        @iter_accounts(accounts=self.accounts)
        def slurp_items(**kwargs):
            # Are we skipping this account?
            if self.check_ignore_list(kwargs["account_name"]):
                app.logger.debug("Skipping ignored account: {}".format(kwargs["account_name"]))
                return [], kwargs["exception_map"]

            # Exception handling complexities...
            results = fetch_security_details(**kwargs)
            if not results:
                return [], kwargs["exception_map"]

            return results

        items, exc = slurp_items(index=self.index)

        return items, exc

    def get_security_details(self, account):
        token = self.azure_creds.get(account).get("token")
        headers = {
                'Authorization': 'Bearer {}'.format(token)
        }

        #subscription = json.loads(azure_cli_general_command(['account', 'list']))[0]['id']
        subscription = self.azure_creds.get(account).get("subscription")
        url = "{}{}/providers/microsoft.Security/policies?api-version=2015-06-01-preview".format(AZURE_URL, subscription)

        result = requests.get(url, headers=headers)

        if result.status_code != 200:
            raise InvalidResponseCodeFromAzureError(account, result.status_code)

        return result.json()


class AzureSecurityCenterItem(ChangeItem):
    def __init__(self, account=None, name=None, arn=None, config=None, source_watcher=None):
        super(AzureSecurityCenterItem, self).__init__(index=AzureSecurityCenter.index,
                                            region="universal",
                                            account=account,
                                            name=name,
                                            arn=arn,
                                            new_config=config if config else {},
                                            source_watcher=source_watcher)
