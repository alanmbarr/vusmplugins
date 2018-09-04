#     Copyright 2018 Veterans United Home Loans
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
.. module: vusmplugins.exceptions
    :platform: Unix
    :synopsis: Utility functions for Security Monkey's Azure Plugin.


.. version:: $$VERSION$$
.. moduleauthor:: Alan Barr <alan.barr@vu.com>

"""
from security_monkey import app, exceptions

class AzureCredsError(exceptions.SecurityMonkeyException):
    """Unable to fetch Azure credentials file"""

    def __init__(self, account):
        self.account = account
        app.logger.info(self)

    def __str__(self):
        return repr("Unable to load Azure credentials for account: {}".format(self.account))

class InvalidResponseCodeFromAzureError(exceptions.SecurityMonkeyException):
    """Unable to fetch data from Azure"""

    def __init__(self, account, response_code):
        self.account = account 
        self.response_code = response_code
        app.logger.info(self)

    def __str__(self):
        return repr("Unable to load data from Azure for the account: {} -- received HTTP response: {}".format(
            self.account, self.response_code
        ))