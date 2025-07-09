import pytest

from taintmonkey.taint import TaintedStr  # Replace with actual import path


def test_creation_and_taint():
    s = TaintedStr("hello")
    assert isinstance(s, TaintedStr)
    assert s == "hello"
    assert s.is_tainted()


def test_sanitize():
    s = TaintedStr("hello")
    s.sanitize()
    assert not s.is_tainted()


def test_addition():
    s1 = TaintedStr("hello")
    s2 = s1 + " world"
    assert isinstance(s2, TaintedStr)
    assert s2 == "hello world"
    assert s2.is_tainted()


def test_multiplication():
    s = TaintedStr("ha")
    repeated = s * 3
    assert repeated == "hahaha"
    assert isinstance(repeated, TaintedStr)
    assert repeated.is_tainted()


def test_indexing():
    s = TaintedStr("abc")
    char = s[1]
    assert char == "b"
    assert isinstance(char, TaintedStr)
    assert char.is_tainted()


@pytest.mark.parametrize(
    "method,input,expected",
    [
        ("upper", TaintedStr("hi"), "HI"),
        ("lower", TaintedStr("HI"), "hi"),
        ("capitalize", TaintedStr("hi"), "Hi"),
        ("title", TaintedStr("hello world"), "Hello World"),
        ("strip", TaintedStr("  test  "), "test"),
        ("replace", TaintedStr("123"), "1a3"),
    ],
)
def test_string_methods(method, input, expected):
    if method == "replace":
        out = input.replace("2", "a")
    else:
        out = getattr(input, method)()
    assert isinstance(out, TaintedStr)
    assert out == expected
    assert out.is_tainted()


def test_join():
    parts = [TaintedStr("a"), TaintedStr("b")]
    sep = TaintedStr(",")
    joined = sep.join(parts)
    assert joined == "a,b"
    assert isinstance(joined, TaintedStr)
    assert joined.is_tainted()


def test_split_rsplit():
    s = TaintedStr("a,b,c")
    left = s.split(",")
    right = s.rsplit(",")
    for part in left + right:
        assert isinstance(part, TaintedStr)
        assert part.is_tainted()


def test_partition_rpartition():
    s = TaintedStr("a=b=c")
    left = s.partition("=")
    right = s.rpartition("=")
    for part in left + right:
        assert isinstance(part, TaintedStr)
        assert part.is_tainted()


def test_format():
    s = TaintedStr("hello {}")
    out = s.format("world")
    assert out == "hello world"
    assert isinstance(out, TaintedStr)
    assert out.is_tainted()


def test_encode_returns_bytes():
    s = TaintedStr("binary")
    encoded = s.encode("utf-8")
    assert isinstance(encoded, bytes)
    assert encoded == b"binary"


def test_repr_and_str():
    s = TaintedStr("foo")
    assert repr(s) == "TaintedStr('foo')"
    assert str(s) == "foo"
