import string
from dataclasses import dataclass, field
from typing import Optional


def _num(s: str) -> Optional[int]:
    # ASCII digits only, because int() also takes Arabic-Indic digits and "3_5". The length cap
    # keeps a hostile header from tripping the int size limit on 3.11 and later, and no PHP
    # component is this long.
    return int(s) if s.isascii() and s.isdigit() and len(s) <= 4 else None


def parse_branch(text: str) -> Optional[tuple[int, int]]:
    """Turn "8.3" into (8, 3). Anything that is not exactly major.minor is None."""
    major, dot, minor = text.strip().partition(".")
    a, b = _num(major), _num(minor)
    return (a, b) if dot and a is not None and b is not None else None


@dataclass(frozen=True, order=True)
class PhpVersion:
    major: int
    minor: int
    micro: int
    # The text after the micro, such as -fpm or -1ubuntu2.28. It stays out of equality, hashing
    # and ordering, so 8.3.35-fpm is the same version as 8.3.35. Only the grader reads it.
    suffix: str = field(default="", compare=False)

    @property
    def branch(self) -> str:
        return f"{self.major}.{self.minor}"

    @classmethod
    def parse(cls, text: str) -> Optional["PhpVersion"]:
        """Read major.minor.micro off the front of text, ignoring a build suffix like -fpm.

        A floating tag ("8.3-apache"), a constraint (">=8.3.36"), or a header line has no
        single micro to grade, so none of them parse.
        """
        major, dot1, rest = text.strip().partition(".")
        minor, dot2, tail = rest.partition(".")
        if not (dot1 and dot2):
            return None
        suffix = tail.lstrip(string.digits)
        micro = tail[:len(tail) - len(suffix)]
        # What follows the micro has to be a build suffix (-fpm, +dfsg, RC1). A further number or
        # a space means this is a range or a header line.
        if suffix and suffix[0] not in "-+~_" + string.ascii_letters:
            return None
        nums = (_num(major), _num(minor), _num(micro))
        return None if None in nums else cls(*nums, suffix)
