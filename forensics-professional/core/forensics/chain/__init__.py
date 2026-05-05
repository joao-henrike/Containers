"""Chain-of-custody capture for shell commands.

The :mod:`forensics.chain.logger` module is invoked from
``bash-hooks.sh`` as a side-effect of every command run by the analyst.
"""

from forensics.chain.logger import record_command

__all__ = ["record_command"]
