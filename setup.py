from setuptools import setup, find_packages

setup(
    name='pyfgt',
    version='0.5.0',
    packages=find_packages(),
    url='https://github.com/p4r4n0y1ng/pyfgt',
    license='Apache 2.0',
    author='p4r4n0y1ng',
    author_email='jhuber@fortinet.com',
    description='Represents the base components of the Fortinet FortiGate REST interface with abstractions',
    include_package_data=True,
    install_requires=['requests']
)
