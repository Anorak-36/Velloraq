"""Legacy worker package path for older imports."""

# SPDX-License-Identifier: MIT
from velloraq.backend import workers as _workers

__path__ = list(_workers.__path__)
