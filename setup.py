# -*- coding: utf-8 -*-
"""Python package config."""
import setuptools

with open('README.md', 'r') as fh:
    long_description = fh.read()

setuptools.setup(
    name='veil-aio-au',
    version='0.1.4',
    author='Aleksey Devyatkin',
    author_email='a.devyatkin@mashtab.org',
    description='VeiL asyncio linux authentication utils.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/jsc-masshtab/veil-aio-au',
    packages=setuptools.find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Development Status :: 4 - Beta',
        'Operating System :: POSIX :: Linux',
    ],
    python_requires='>=3.5',
    install_requires=['python-pam==1.8.*', ]
)
