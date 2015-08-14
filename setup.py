from setuptools import setup, find_packages
from os import path


PWD = path.abspath(path.dirname(__file__))

with open(path.join(PWD, 'README.rst')) as fp:
    long_description = fp.read()

with open(path.join(PWD, 'requirements.txt')) as fp:
    install_requires = [line.strip() for line in fp.readlines()]

setup(
    name='wifi-monitor',
    verion='0.0.0',
    description='Detect instruders using Wi-Fi monitor mode.',
    long_description=long_description,
    url='https://github.com/kjwon15/wifi-monitor',
    author='Kjwon15',
    author_email='kjwonmail@gmail.com',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Console',
        'Topic :: Home Automation',
        'Topic :: Internet',
    ],
    keywords='wifi security',
    packages=find_packages(),
    install_requires=install_requires,
)
