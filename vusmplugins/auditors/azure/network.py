"""
.. module: vusmplugins.auditors.azure.network
    :platform: Unix
    :synopsis: Auditor for Azure Security Center


.. version:: $$VERSION$$

"""
from security_monkey import app
from security_monkey.auditor import Auditor
from vusmplugins.watchers.azure.network import AzureNetwork
import jmespath

class AzureNetworkAuditor(Auditor):
    index = AzureNetwork.index
    i_am_singular = AzureNetwork.i_am_singular
    i_am_plural = AzureNetwork.i_am_plural

    app.logger.debug("initializing auditor class")

    def __init__(self, accounts=None, debug=False):
        app.logger.debug("constructing auditor")
        super(AzureNetworkAuditor, self).__init__(accounts=accounts, debug=debug)

    def check_for_rdp_allowed(self, item):
        """
        Check access is not too open
        :param security_details:
        :return:
        """
        tag = "Access is too open and set to Allow"
        

        
        allow = item.config.get("access") == "Allow"
        portRange = item.config.get("destinationPortRange") == "3389" or item.config.get("destinationPortRange") == "*"
        direction = item.config.get("direction") == "Inbound"
        protocol = item.config.get("protocol") == "TCP"
        pfx = item.config.get("sourceAddressPrefix")
        sourceAddr = pfx == "*" or pfx == "0.0.0.0" or pfx == "<nw>/0" or pfx == "/0" or pfx == "internet" or pfx == "any"
        if allow and portRange and direction and protocol and sourceAddr:
            self.add_issue(10, tag, item, notes="RDP is open")
        else:
            app.logger.debug("auditing failed to find issue")
            pass
