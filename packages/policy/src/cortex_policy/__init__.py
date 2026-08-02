"""The Cortex security boundary.

Public surface is deliberately small: build an operation, build a context, call
:func:`decide`. Everything else in this package is an implementation detail of that
one function.

    >>> from cortex_policy import ShellOperation, decide
    >>> decide(ShellOperation(command="rm -rf /")).verdict
    <Verdict.DENY: 'deny'>
"""

from .denylist import DenyMatch
from .engine import decide
from .paths import Containment, PathSensitivity, contains, sensitivity
from .risk import (
    AUTO_AT_LEVEL,
    AutonomyLevel,
    Decision,
    FileAction,
    FileOperation,
    NetworkOperation,
    Operation,
    PolicyContext,
    RiskClass,
    ShellOperation,
    Verdict,
)
from .shellparse import ParseProblem

__all__ = [
    "AUTO_AT_LEVEL",
    "AutonomyLevel",
    "Containment",
    "Decision",
    "DenyMatch",
    "FileAction",
    "FileOperation",
    "NetworkOperation",
    "Operation",
    "ParseProblem",
    "PathSensitivity",
    "PolicyContext",
    "RiskClass",
    "ShellOperation",
    "Verdict",
    "contains",
    "decide",
    "sensitivity",
]
