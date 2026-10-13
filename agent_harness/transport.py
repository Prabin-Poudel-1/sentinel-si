"""Deadline-bounded pipe exchange; Windows never uses socket-only select on pipes."""
import os
import queue
import select
import threading
import time

MAX_RESPONSE = 262144


def _blocking_exchange(process, wire):
    offset = 0
    while offset < len(wire):
        count = os.write(process.stdin.fileno(), wire[offset:offset + 512])
        if count <= 0:
            raise EOFError()
        offset += count
    received = bytearray()
    while b"\n" not in received:
        chunk = os.read(process.stdout.fileno(), 65536)
        if not chunk:
            raise EOFError()
        received.extend(chunk)
        if len(received) > MAX_RESPONSE:
            raise ValueError("Oversized response")
    return bytes(received)


def exchange(process, wire, timeout, *, threaded=None):
    """Caller serializes calls. A timeout kills the child, never falls back to a tool.

    On Windows a worker owns blocking pipe I/O. Terminating the owned child closes
    its pipe ends and unblocks the worker. The caller has a bounded wait even if a
    compromised child has passed a pipe to another process (outside this runtime).
    """
    if len(wire) > 8 * 1024 * 1024:
        raise ValueError("Oversized request")
    use_thread = os.name == "nt" if threaded is None else threaded
    if use_thread:
        result = queue.Queue(maxsize=1)
        def worker():
            try:
                result.put((True, _blocking_exchange(process, wire)))
            except Exception as error:
                result.put((False, error))
        thread = threading.Thread(target=worker, daemon=True, name="sentinel-pipe")
        thread.start()
        try:
            success, value = result.get(timeout=timeout)
        except queue.Empty:
            if process.poll() is None:
                process.kill()
            thread.join(timeout=0.5)
            raise TimeoutError("Gateway pipe deadline") from None
        thread.join(timeout=0.5)
        if not success:
            raise value
        received = value
    else:
        deadline = time.monotonic() + timeout
        offset = 0
        while offset < len(wire):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([], [process.stdin], [], remaining)[1]:
                raise TimeoutError()
            count = os.write(process.stdin.fileno(), wire[offset:offset + 512])
            if count <= 0:
                raise EOFError()
            offset += count
        received = bytearray()
        while b"\n" not in received:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                raise TimeoutError()
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk:
                raise EOFError()
            received.extend(chunk)
            if len(received) > MAX_RESPONSE:
                raise ValueError("Oversized response")
    if received.count(b"\n") != 1 or received[-1:] != b"\n":
        raise ValueError("Unexpected response frames")
    return received
