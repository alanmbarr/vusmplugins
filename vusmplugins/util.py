"""
.. module: vusmplugins.util
    :platform: Unix
    :synopsis: Utility functions for Security Monkey's Azure Plugin.


.. version:: $$VERSION$$
.. moduleauthor:: Alan Barr <alan.barr@vu.com>

"""
import json
from functools import wraps
from security_monkey import app
from security_monkey.datastore import Account
from vusmplugins.exceptions import AzureCredsError
from six import StringIO
from subprocess import call

"""
Should be replaced with az login and a service principal account
https://docs.microsoft.com/en-us/python/azure/python-sdk-azure-authenticate?view=azure-python
az ad sp create-for-rbac --name ServicePrincipalName --password PASSWORD
az login --service-principal -u <app-url> -p <password-or-cert> --tenant <tenant>
File Based Authentication
az ad sp create-for-rbac --sdk-auth > mycredentials.json

"""
def get_azure_creds(account_names):
    """
    Grab Azure credentials from a JSON file on disk.

    The json looks like this:
        {
            "Account-Name": {
                "token": "API KEY",
                "subscription": "SUBSCRIPTION ID"
            }
        },
        {
            "Account-Name-2": 
             {
                "token": "API KEY",
                "subscription": "SUBSCRIPTION ID"
             }
        }
        ...

    :param account_names: list of account names
    :type account_names: ``list``
    """
    # The name of the field as defined in the Azure Account Manager.
    creds_field = 'access_token_file'
    org_creds = {}

    accounts = Account.query.filter(Account.name.in_(account_names)).all()

    for account in accounts:
        try:
            if not org_creds.get(account.identifier):
                creds_file = account.getCustom(creds_field)
                if creds_file:
                    with open(creds_file, "r") as file:
                        creds_dict = json.loads(file.read())

                    org_creds.update(creds_dict)
                else:
                    org_creds.update(app.config.get("AZURE_CREDENTIALS"))
        except Exception as _:
            raise AzureCredsError(account.identifier)

    return org_creds


def iter_accounts(accounts):
    """
    Decorator for looping over many Azure tokens.

    This will pass in the exception map properly.
    :param orgs:
    :return:
    """
    def decorator(func):
        @wraps(func)
        def decorated_function(*args, **kwargs):
            item_list = []
            if not kwargs.get("exception_map"):
                kwargs["exception_map"] = {}

            for account in accounts:
                kwargs["account_name"] = account 
                item, exc = func(*args, **kwargs)
                item_list.extend(item)

            return item_list, kwargs["exception_map"]

        return decorated_function

    return decorator

def azure_cli_login_with_service_principal(account_names):
    # The name of the field as defined in the Azure Account Manager.
    creds_field = 'access_token_file'
    org_creds = {}

    accounts = Account.query.filter(Account.name.in_(account_names)).all()

    for account in accounts:
        try:
            if not org_creds.get(account.identifier):
                creds_file = account.getCustom(creds_field)
                if creds_file:
                    # don't allow override from file
                    # just use the settings
                    #org_creds.update(creds_dict)
                    pass
                else:
                    org_creds.update(app.config.get("AZURE_CREDENTIALS"))
        except Exception as _:
            raise AzureCredsError(account.identifier)
        # /usr/bin/az login --service-principal --username 8c3673b3-9310-40d4-857d-d08115bc471b --password /usr/local/src/security_monkey/env-config/tmpjXm0RR.pem --tenant f8ff6e6b-7337-47d6-8e7e-f961f8836708
        
        azure_cli_general_command(['login', '--service-principal', '--username', creds_file['appID_ServicePrincipal'],'--password', creds_file['password'], '--tenant', account.identifier])

    return org_creds

def azure_cli_general_command( cliArgArray ):
    io = StringIO()
    call(['/usr/bin/az'] + cliArgArray, stdout=io)
    return io.getvalue()


    
