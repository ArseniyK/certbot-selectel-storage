from distutils.core import setup

from setuptools import find_packages

install_requires = [
    'python-swiftclient'
]

setup(
    name='certbot-selectel-storage',
    version='0.1.0',
    description="OpenStack/Selectel storage plugin for Certbot client",
    url='https://github.com/ArseniyK/certbot-selectel-storage',
    author="Arseniy Krasnov",
    author_email='arseniy@krasnoff.org',
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],
    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    keywords=['certbot', 'selectel'],
    entry_points={
        'certbot.plugins': [
            'auth = certbot_selectel_storage.selectel_storage:Authenticator',
            'installer = certbot_selectel_storage.selectel_storage:Installer',
        ],
    },
)