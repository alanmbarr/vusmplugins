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
from port_range import PortRange

class AzureNetworkAuditor(Auditor):
    index = AzureNetwork.index
    i_am_singular = AzureNetwork.i_am_singular
    i_am_plural = AzureNetwork.i_am_plural

    def __init__(self, accounts=None, debug=False):
        super(AzureNetworkAuditor, self).__init__(accounts=accounts, debug=debug)

    def check_for_rdp_allowed(self, item):
        """
        Check access is not open for RDP
        :param security_details:
        :return:
        """
        tag = "RDP is allowed"
        
        portRange = False
        ports = item.config.get("destinationPortRange").split(",")
        if "*" in ports or "3389" in ports:
            portRange = True
        else:
            pr = PortRange(ports)
            if pr.port_from <= 3389 <= pr.port_to:
                portRange = True
            
        allow = item.config.get("access") == "Allow"
        direction = item.config.get("direction") == "Inbound"
        protocol = item.config.get("protocol") == "TCP"
        pfx = item.config.get("sourceAddressPrefix")
        sourceAddr = pfx == "*" or pfx == "0.0.0.0" or pfx == "<nw>/0" or pfx == "/0" or pfx == "internet" or pfx == "any"
        if allow and portRange and direction and protocol and sourceAddr:
            self.add_issue(10, tag, item, notes="RDP is open")

    def check_for_ssh_allowed(self, item):
        """
        Check access is not open for SSH
        :param security_details:
        :return:
        """
        tag = "SSH is allowed"

        portRange = False
        ports = item.config.get("destinationPortRange").split(",")
        if "*" in ports or "22" in ports:
            portRange = True
        else:
            pr = PortRange(ports)
            if pr.port_from <= 22 <= pr.port_to:
                portRange = True
                
        allow = item.config.get("access") == "Allow"
        direction = item.config.get("direction") == "Inbound"
        protocol = item.config.get("protocol") == "TCP"
        pfx = item.config.get("sourceAddressPrefix")
        sourceAddr = pfx == "*" or pfx == "0.0.0.0" or pfx == "<nw>/0" or pfx == "/0" or pfx == "internet" or pfx == "any"
        if allow and portRange and direction and protocol and sourceAddr:
            self.add_issue(10, tag, item, notes="SSH is open")
