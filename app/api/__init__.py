"""Legacy API package path for older imports."""

# SPDX-License-Identifier: MIT
from velloraq.backend import api as _api

__path__ = list(_api.__path__)
