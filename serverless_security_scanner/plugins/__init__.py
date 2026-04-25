"""Legacy plugin package path for older imports."""

# SPDX-License-Identifier: MIT
from velloraq import plugins as _plugins

__path__ = list(_plugins.__path__)
