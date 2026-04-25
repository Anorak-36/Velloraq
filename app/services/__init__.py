"""Legacy service package path for older imports."""

# SPDX-License-Identifier: MIT
from velloraq.backend import services as _services

__path__ = list(_services.__path__)
