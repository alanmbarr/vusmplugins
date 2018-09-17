"""
.. module: security_monkey.vusmplugins.account_managers.azure_account
    :platform: Unix
    :synopsis: Manages generic azure account.


.. version:: $$VERSION$$
.. moduleauthor:: VU


"""
from security_monkey.account_manager import AccountManager, CustomFieldConfig


class AzureAccountManager(AccountManager):
    account_type = 'Azure'
    identifier_label = 'Organization Name'
    identifier_tool_tip = 'Enter the Azure AD Tenant ID'
    access_token_tool_tip = "Enter the path to the file that contains the Azure personal access token."
    service_principal_tool_tip = "Enter ID for service principal."
    password_tool_tip = "Enter password or path to cert PEM file."
    custom_field_configs = [
        CustomFieldConfig('access_token_file', "Personal Access Token", True, access_token_tool_tip),
        CustomFieldConfig('appID_ServicePrincipal', "ServicePrincipal Application ID", True, service_principal_tool_tip),
        CustomFieldConfig('password', "Password (or path to PEM file)", True, password_tool_tip),
    ]

    def __init__(self):
        super(AccountManager, self).__init__()
