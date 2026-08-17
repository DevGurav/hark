"""In-process capture of the nondeterminism the network boundary cannot see.

The mediator records everything the agent sends or receives, but a clock read and
a random draw never cross it. Both change what an agent does -- a timestamp in a
prompt, a request id, a sampled choice -- so replay needs them too.

Python imports ``sitecustomize`` automatically at interpreter startup if it is on
``PYTHONPATH``, before any user code runs. That is early enough to patch the
functions before the agent can hold a reference to the originals.

Two things this is honest about:

* It is **advisory**. The agent could delete this from its ``PYTHONPATH`` or call
  the underlying syscalls directly. Network fidelity is enforced by the kernel;
  clock and RNG fidelity are best-effort. ``docs/security.md`` says so.
* It costs a socket round trip per call. Fine for an agent making a handful of
  draws, not for one in a tight loop. Recorded as a known limit rather than
  hidden.

Failure is loud on purpose. A shim that cannot reach the supervisor and carries
on would produce a recording that looks complete and can never replay, which is
the kind of failure nobody notices until they need the artifact.
"""

import json
import os
import socket
import sys
import threading

# Re-entrancy guard.
#
# Some patched functions are implemented in terms of others: uuid.uuid4 calls
# os.urandom. Without a guard, recording captures both the inner draw and the
# outer result, while replay serves the outer one from its own queue and never
# consumes the inner -- so the queues drift apart and a later os.urandom is
# answered with bytes recorded for something else.
#
# That is precisely the silent failure this whole design is meant to avoid: the
# replay reports success while the agent sees a value it never saw. Only the
# outermost capture is recorded, so record and replay consume in step.
#
# Thread-local because an agent may draw randomness from several threads, and a
# global flag would let one thread suppress another's capture.
_local = threading.local()


def _entered():
    return getattr(_local, "capturing", False)


class _outermost:
    """True only for the outermost patched call on this thread."""

    def __enter__(self):
        self.previous = _entered()
        _local.capturing = True
        return not self.previous

    def __exit__(self, *_):
        _local.capturing = self.previous
        return False

_SOCKET = os.environ.get("HARK_SHIM_SOCKET")
_MODE = os.environ.get("HARK_SHIM_MODE")  # "record", "replay" or "fork"


def _fail(message):
    sys.stderr.write("hark shim: %s\n" % message)
    # 126 matches what the launcher uses for "the containment could not be set
    # up", because that is what this is.
    #
    # sys.exit raises SystemExit, which derives from BaseException. That matters:
    # site.py wraps sitecustomize in `except Exception`, so an ordinary exception
    # here is caught, reduced to a one-line "Error in sitecustomize" warning, and
    # the interpreter carries on unpatched. SystemExit passes straight through.
    sys.exit(126)


class _Channel:
    """One request/response at a time over a unix socket.

    Newline-delimited JSON rather than a binary framing: this is a low-volume
    control channel, and being able to read it with ``socat`` while debugging is
    worth more than the bytes.
    """

    def __init__(self, path):
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self._sock.connect(path)
        except OSError as exc:
            _fail("cannot reach the supervisor at %s: %s" % (path, exc))
        self._file = self._sock.makefile("rwb")

    def call(self, op, src, val=None):
        msg = {"op": op, "src": src}
        if val is not None:
            msg["val"] = val
        try:
            self._file.write((json.dumps(msg) + "\n").encode())
            self._file.flush()
            line = self._file.readline()
        except OSError as exc:
            _fail("lost the supervisor connection: %s" % exc)
        if not line:
            _fail("the supervisor closed the connection")

        reply = json.loads(line)
        if not reply.get("ok"):
            # In replay this means the recording has nothing left for this
            # source: the run diverged. Refusing beats inventing a value.
            _fail(reply.get("err", "unknown error"))
        return reply


_channel = None


def _record(src, value):
    _channel.call("rec", src, value)
    return value


def _replay(src):
    return _channel.call("get", src).get("val")


def _obtain(src, produce, encode=None, decode=None):
    """Return a value for src, honouring the mode.

    Recording draws for real and reports the value. Replay asks for the recorded
    one and never draws. A fork does both, in that order: recorded values up to
    its branch point, then real ones -- and the supervisor is the one that says
    when, because it is the side that knows how far the verified prefix got.

    The value is produced here rather than by the supervisor because only this
    process can make one of the right shape. A ``uuid.UUID`` the agent's own
    module accepts is not something to reconstruct from the other end of a
    socket.
    """
    if _MODE == "record":
        v = produce()
        _record(src, v if encode is None else encode(v))
        return v

    reply = _channel.call("get", src)
    if reply.get("live"):
        v = produce()
        _record(src, v if encode is None else encode(v))
        return v

    val = reply.get("val")
    return val if decode is None else decode(val)


def _draw(src, produce, encode=None, decode=None):
    """_obtain, for the sources that nest.

    uuid4 calls os.urandom underneath, and both are patched. Only the outermost
    call is captured; an inner one is served the real thing and left off the
    record, or the queues drift apart and a later draw is answered with bytes
    recorded for something else.
    """
    with _outermost() as outer:
        if not outer:
            return produce()
        return _obtain(src, produce, encode, decode)


def _install():
    import random
    import time
    import uuid

    # --- clock -----------------------------------------------------------
    # Both the float and _ns variants are patched. Python's own libraries reach
    # for whichever suits them, and leaving one unpatched would let a run read an
    # unrecorded clock through the back door.
    #
    # No re-entrancy guard here: a clock read cannot nest inside another.

    def _clock(name, real):
        def fn():
            return _obtain(name, real)
        return fn

    time.time = _clock("time.time", time.time)
    time.monotonic = _clock("time.monotonic", time.monotonic)
    time.time_ns = _clock("time.time_ns", time.time_ns)
    time.monotonic_ns = _clock("time.monotonic_ns", time.monotonic_ns)

    # --- randomness ------------------------------------------------------
    # Recorded per draw rather than by seeding.
    #
    # Re-seeding would be far cheaper, and it does not work: the agent can create
    # its own random.Random instances, and any library it imports may consume
    # draws in numbers that change between versions. Recording each value is
    # slower and actually reproduces what happened.

    real_random, real_getrandbits = random.random, random.getrandbits
    real_urandom = os.urandom
    real_uuid4 = uuid.uuid4

    def _random():
        return _draw("random.random", real_random)

    def _getrandbits(k):
        return _draw("random.getrandbits", lambda: real_getrandbits(k))

    def _urandom(n):
        return _draw("os.urandom", lambda: real_urandom(n),
                     encode=lambda v: v.hex(), decode=bytes.fromhex)

    def _uuid4():
        return _draw("uuid.uuid4", real_uuid4, encode=str, decode=uuid.UUID)

    random.random = _random
    random.getrandbits = _getrandbits
    os.urandom = _urandom
    uuid.uuid4 = _uuid4

    # The module-level helpers are bound methods of a hidden Random instance, so
    # patching random.random alone leaves randint, choice and shuffle drawing
    # from the unpatched generator. Rebinding the instance's methods catches all
    # of them at once.
    random._inst.random = _random
    random._inst.getrandbits = _getrandbits


if _SOCKET and _MODE:
    if _MODE not in ("record", "replay", "fork"):
        _fail("HARK_SHIM_MODE must be 'record', 'replay' or 'fork', got %r" % _MODE)
    if not hasattr(socket, "AF_UNIX"):
        _fail("this interpreter has no AF_UNIX support; hark runs on Linux")

    # Everything below is wrapped, because site.py catches Exception around this
    # module and turns any failure into a warning the run would otherwise
    # continue past -- recording nothing, and looking fine while doing it.
    # Converting to SystemExit is what makes a broken shim stop the run.
    try:
        _channel = _Channel(_SOCKET)
        _install()
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - deliberately broad
        _fail("could not install: %r" % (exc,))
