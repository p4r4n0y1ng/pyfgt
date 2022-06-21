from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_desc = fh.read()

setup(
    name='pyfgt',
    version='0.5.6',
    packages=find_packages(),
    url='https://github.com/p4r4n0y1ng/pyfgt',
    license='Apache 2.0',
    author='p4r4n0y1ng',
    author_email='jhuber@fortinet.com',
    description='Represents the base components of the Fortinet FortiGate REST interface with abstractions',
    long_description=long_desc,
    long_description_content_type="text/markdown",
    include_package_data=True,
    install_requires=['requests']
)
