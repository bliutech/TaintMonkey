"""
Special tainted data types for primitive data types.
"""

from typing import override


# TODO(bliutech): see if we can incorperate this
class TaintedMixin:
    def __init__(self):
        self.tainted = True

    def sanitize(self):
        self.tainted = False

    def is_tainted(self) -> bool:
        return self.tainted


class TaintedStr(str):
    """
    A tainted string data type.

    Example.
    s1 = TaintedStr("hello")
    s2 = s1 + " world"
    print(repr(s2))     # TaintedStr('hello world')
    print(s2.tainted)   # True
    s2.sanitize()
    print(s2.is_tainted()) # False
    """

    def __new__(cls, value: str):
        obj = super().__new__(cls, value)
        # TODO(bliutech): this is wrong. a TaintedStr object can potentially get constructed
        # after it has been sanitized
        obj.tainted = True  # type: ignore
        return obj

    def sanitize(self):
        self.tainted = False  # type: ignore

    def is_tainted(self) -> bool:
        return self.tainted

    def _wrap(self, result):
        """Helper method to wrap result in TaintedStr if it's a string."""
        if isinstance(result, str):
            return TaintedStr(result)
        else:
            return result

    # Common string operations
    def __add__(self, other):
        return self._wrap(super().__add__(other))

    # def __radd__(self, other):
    #     return self._wrap(super().__radd__(other))

    def __mul__(self, n):
        return self._wrap(super().__mul__(n))

    def __rmul__(self, n):
        return self._wrap(super().__rmul__(n))

    def __getitem__(self, key):
        return self._wrap(super().__getitem__(key))

    @override
    def replace(self, old, new, maxsplit=-1):  # type: ignore
        return self._wrap(super().replace(old, new, maxsplit))

    @override
    def join(self, iterable):  # type: ignore
        return self._wrap(super().join(str(x) for x in iterable))

    @override
    def upper(self):  # type: ignore
        return self._wrap(super().upper())

    @override
    def lower(self):  # type: ignore
        return self._wrap(super().lower())

    @override
    def capitalize(self):  # type: ignore
        return self._wrap(super().capitalize())

    @override
    def title(self):  # type: ignore
        return self._wrap(super().title())

    @override
    def strip(self, chars=None):  # type: ignore
        return self._wrap(super().strip(chars))

    @override
    def lstrip(self, chars=None):  # type: ignore
        return self._wrap(super().lstrip(chars))

    @override
    def rstrip(self, chars=None):  # type: ignore
        return self._wrap(super().rstrip(chars))

    @override
    def split(self, sep=None, maxsplit=-1):  # type: ignore
        return [self._wrap(s) for s in super().split(sep, maxsplit)]

    @override
    def rsplit(self, sep=None, maxsplit=-1):  # type: ignore
        return [self._wrap(s) for s in super().rsplit(sep, maxsplit)]

    @override
    def partition(self, sep):  # type: ignore
        return tuple(self._wrap(part) for part in super().partition(sep))

    @override
    def rpartition(self, sep):  # type: ignore
        return tuple(self._wrap(part) for part in super().rpartition(sep))

    @override
    def format(self, *args, **kwargs):  # type: ignore
        return self._wrap(super().format(*args, **kwargs))

    @override
    def encode(self, encoding="utf-8", errors="strict"):
        # TODO(bliutech): may want to add a TaintedBytes data type.
        # encoding returns bytes, so don't wrap
        return super().encode(encoding, errors)

    @override
    def __str__(self):  # type: ignore
        return self._wrap(super().__str__())

    # TODO(bliutech): a current issue is that Python's builtin f-strings
    # return a `str` by default and its not obvious how to override them.
    # TODO(bliutech): another issue is that builtin strings return a string
    # when you have str.format(TaintedStr)
    @override
    def __format__(self, format_spec):
        return self._wrap(super().__format__(format_spec))

    @override
    def __repr__(self):
        # TODO(bliutech): potentially we may want a tainted string here
        return f"TaintedStr({super().__repr__()})"


# TODO(bliutech): add other primitive data types such as ints, bytes, etc
