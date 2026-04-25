"""Legacy compatibility package for the former project name.

New code should import from ``velloraq``. This package forwards common imports
so installed users have a gentle migration path.
"""

# SPDX-License-Identifier: MIT
from velloraq import __version__

__all__ = ["__version__"]
