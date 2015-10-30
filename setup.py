from setuptools import setup, find_packages
from os import path


PWD = path.abspath(path.dirname(__file__))

with open(path.join(PWD, 'README.rst')) as fp:
    long_description = fp.read()

install_requires = [
    'PyYAML>=3.11',
    'gTTS>=1.0.6',
    'pyttsx>=1.1',
    'redis>=2.10.3',
    'scapy>=2.3.1',
]

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
    entry_points={
        'console_scripts': [
            'wifi-monitor=wifimonitor.app:main'
        ]
    },
)
