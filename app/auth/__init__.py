"""Legacy auth package path for older imports."""

# SPDX-License-Identifier: MIT
from velloraq.backend import auth as _auth

__path__ = list(_auth.__path__)
