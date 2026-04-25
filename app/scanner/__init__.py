"""Legacy SaaS scanner adapter package path for older imports."""

# SPDX-License-Identifier: MIT
from velloraq.backend import scanner as _scanner

__path__ = list(_scanner.__path__)
