"""
.. module: vusmplugins.watchers.ad
    :platform: Unix
    :synopsis: Watcher for Azure Active Directory.


.. version:: $$VERSION$$
.. moduleauthor:: Alan Barr <alan.barr@vu.com>

"""
from security_monkey import app
from vusmplugins.util import azure_cli_general_command, azure_cli_login_with_service_principal, iter_accounts
from security_monkey.datastore import Account
from security_monkey.decorators import record_exception
from vusmplugins.exceptions import InvalidResponseCodeFromAzureError
from security_monkey.watcher import Watcher, ChangeItem


class AzureActiveDirectory(Watcher):
    index = 'ad'
    i_am_singular = 'ad'
    i_am_plural = 'ad'
    account_type = 'Azure'

    def __init__(self, accounts=None, debug=False):
        super(AzureActiveDirectory, self).__init__(accounts=accounts, debug=debug)

    def slurp(self):
        @record_exception(source="{index}-watcher".format(index=self.index))
        def fetch_active_directory_details(**kwargs):
            item_list = []
            account = Account.query.filter(Account.name == kwargs["account_name"]).first()

            # Fetch the initial Azure Security Center details:
            app.logger.debug("Fetching initial org details for: {}".format(account.identifier))
            security_details = self.get_security_details(account.identifier)

            item_list.append(AzureActiveDirectoryItem(
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
            results = fetch_active_directory_details(**kwargs)
            if not results:
                return [], kwargs["exception_map"]

            return results

        items, exc = slurp_items(index=self.index)

        return items, exc

    def get_security_details(self, account):

        azure_cli_login_with_service_principal(account)
        
        # Benchmark 1.3 az ad user list --query "[?additionalProperties.userType=='Guest']"
        #  '--query', '"[?additionalProperties.userType==\'Guest\']"']
        cliArgArray = ['ad', 'user', 'list']

        result = azure_cli_general_command( cliArgArray )

        return result
        
class AzureActiveDirectoryItem(ChangeItem):
    def __init__(self, account=None, name=None, arn=None, config=None, source_watcher=None):
        super(AzureActiveDirectoryItem, self).__init__(index=AzureActiveDirectory.index,
                                            region="universal",
                                            account=account,
                                            name=name,
                                            arn=arn,
                                            new_config=config if config else {},
                                            source_watcher=source_watcher)
