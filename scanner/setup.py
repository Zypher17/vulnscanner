# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

setup(
    name="vulnscanner",
    version="2.2",
    packages=find_packages(),
    install_requires=[
        "httpx",
        "rich",
        "PyYAML",
    ],
)
