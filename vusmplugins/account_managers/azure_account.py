#     Copyright 2018 Veterans United Home Loans, LLC
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
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
        super(AzureAccountManager, self).__init__()
