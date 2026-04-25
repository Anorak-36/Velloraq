"""Legacy ORM model package path for older imports."""

# SPDX-License-Identifier: MIT
from velloraq.backend import models as _models

__path__ = list(_models.__path__)
