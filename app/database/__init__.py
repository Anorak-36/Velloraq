"""Legacy database package path for older imports."""

# SPDX-License-Identifier: MIT
from velloraq.backend import database as _database

__path__ = list(_database.__path__)
