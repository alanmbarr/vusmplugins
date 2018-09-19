"""
.. module: vusmplugins.watchers.network
    :platform: Unix
    :synopsis: Watcher for Azure Active Directory.


.. version:: $$VERSION$$
.. moduleauthor:: 

"""
from security_monkey import app
from vusmplugins.util import azure_cli_general_command, azure_cli_login_with_service_principal, iter_accounts
from security_monkey.datastore import Account
from security_monkey.decorators import record_exception
from vusmplugins.exceptions import InvalidResponseCodeFromAzureError
from security_monkey.watcher import Watcher, ChangeItem
import jmespath, json

class AzureNetwork(Watcher):
    index = 'network'
    i_am_singular = 'network'
    i_am_plural = 'network'
    account_type = 'Azure'

    def __init__(self, accounts=None, debug=False):
        super(AzureNetwork, self).__init__(accounts=accounts, debug=debug)

    def slurp(self):
        @record_exception(source="{index}-watcher".format(index=self.index))
        def fetch_details(**kwargs):
            item_list = []
            account = Account.query.filter(Account.name == kwargs["account_name"]).first()

            # Fetch the initial Azure Security Center details:
            app.logger.debug("Fetching initial org details for: {}".format(account.identifier))
            security_details = self.get_security_details(account.identifier)

            item_list.append(AzureNetworkItem(
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
            results = fetch_details(**kwargs)
            if not results:
                return [], kwargs["exception_map"]

            return results

        items, exc = slurp_items(index=self.index)

        return items, exc

    def get_security_details(self, account):

        azure_cli_login_with_service_principal(account)

        # REPLACE ME
        cliArgArray = ['network', 'nsg', 'list', '--query', '"[].[name,securityRules]"']

        result = azure_cli_general_command( cliArgArray )
        result = json.loads(result)
        transformed = [match for match in jmespath.compile('[].securityRules[]').search(result)]

        newDict = {}
        for item in transformed:
            allow = item.get("access")
            portRange = item.get("destinationPortRange")
            direction = item.get("direction")
            protocol = item.get("protocol")
            pfx = item.get("sourceAddressPrefix")
        newDict.update(access=allow, destinationPortRange=portRange, direction=direction, protocol=protocol, sourceAddressPrefix=pfx)
        app.logger.debug(newDict)
        return newDict
        
class AzureNetworkItem(ChangeItem):
    def __init__(self, account=None, name=None, arn=None, config=None, source_watcher=None):
        super(AzureNetworkItem, self).__init__(index=AzureNetwork.index,
                                            region="universal",
                                            account=account,
                                            name=name,
                                            arn=arn,
                                            new_config=config if config else {},
                                            source_watcher=source_watcher)
