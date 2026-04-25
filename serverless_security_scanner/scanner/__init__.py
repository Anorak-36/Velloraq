"""Legacy scan engine package path for older imports."""

# SPDX-License-Identifier: MIT
from velloraq import scanner as _scanner

__path__ = list(_scanner.__path__)
