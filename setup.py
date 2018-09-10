from setuptools import setup, find_packages

setup(
    name="vusmplugins",
    version="0.1-dev0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=["security_monkey","jmespath"],
    entry_points={
        "security_monkey.plugins": [
            "vusmplugins.account_managers.azure_account = vusmplugins.account_managers.azure_account",
            "vusmplugins.watchers.azure.ad = vusmplugins.watchers.azure.ad"
        ]
    }
)
