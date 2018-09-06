"""
.. module: vusmplugins.auditors.azure.security_center
    :platform: Unix
    :synopsis: Auditor for Azure Security Center


.. version:: $$VERSION$$
.. moduleauthor:: Alan Barr <alan.barr@vu.com> 

"""
from security_monkey import app
from security_monkey.auditor import Auditor
from vusmplugins.watchers.azure.security_center import AzureSecurityCenter
import jmespath

class AzureSecurityCenterAuditor(Auditor):
    index = AzureSecurityCenter.index
    i_am_singular = AzureSecurityCenter.i_am_singular
    i_am_plural = AzureSecurityCenter.i_am_plural

    app.logger.debug("initializing auditor class")

    def __init__(self, accounts=None, debug=False):
        app.logger.debug("constructing auditor")
        super(AzureSecurityCenterAuditor, self).__init__(accounts=accounts, debug=debug)

    def check_for_provisioning_monitoring_agent(self, item):
        """
        Check that security agent is collecting data 
        :param security_details:
        :return:
        """
        tag = "Account contains policy with security monitoring agent off."
        app.logger.debug(item) 
        result = [match for match in jmespath.compile('value[*].properties.logCollection').search(item.config)]
#        result = [match.value for match in parse("$.value[*].properties.logCollection").find(security_details.config)]

        if "Off" in result:
            self.add_issue(10, tag, item, notes="Account contains unprovisioned monitoring agents")
        else:
            app.logger.debug("nothing found") 

    def check_fake_issue(self, item):
        tag = "Account is not fun"
        app.logger.debug(item) 
        self.add_issue(100, tag, item, notes="problems!!!")
