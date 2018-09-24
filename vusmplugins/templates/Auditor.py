"""
.. module: vusmplugins.auditors.azure.__SHORTNAME__
    :platform: Unix
    :synopsis: Auditor for Azure Security Center


.. version:: $$VERSION$$

"""
from security_monkey import app
from security_monkey.auditor import Auditor
from vusmplugins.watchers.__WATCHERNAMESPACE__ import __WATCHER__

class __NAME__Auditor(Auditor):
    index = __WATCHERNAMESPACE__.index
    i_am_singular = __WATCHERNAMESPACE__.i_am_singular
    i_am_plural = __WATCHERNAMESPACE__.i_am_plural

    app.logger.debug("initializing auditor class")

    def __init__(self, accounts=None, debug=False):
        super(__NAME__Auditor, self).__init__(accounts=accounts, debug=debug)

    def check_for_provisioning_monitoring_agent(self, item):
        """
        Check that security agent is collecting data 
        :param security_details:
        :return:
        """
        tag = "Account contains policy with security monitoring agent off."
        ## Do Something with the security item and mark an issue if it doesn't comply
        result = [match for match in jmespath.compile('value[*].properties.logCollection').search(item.config)]

        if "Off" in result:
            self.add_issue(10, tag, item, notes="Account contains unprovisioned monitoring agents")
        
