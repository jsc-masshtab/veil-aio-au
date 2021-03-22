# -*- coding: utf-8 -*-

"""VeiL asyncio linux authentication utils.

for additional info see README.md
"""

__version__ = '0.1.4'

from .veil_au import VeilAuthPam, VeilResult

__all__ = (
    'VeilAuthPam', 'VeilResult'
)

__author__ = 'Aleksey Devyatkin <a.devyatkin@mashtab.org>'
