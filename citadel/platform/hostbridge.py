"""The daemon's link to the macOS host app (Citadel.app), which talks to the
network filter system extension. It plays the part citadel-helper plays on
Linux: the daemon's helper calls (status, apply, off, kill, resolve) go here
instead of through pkexec.

JSON lines over a Unix socket ($TMPDIR/citadel/host.sock):
  daemon -> host   {"id": 1, "cmd": "apply", "args": {"spec": {...}}}
  host -> daemon   {"id": 1, "code": 0, "out": "...", "err": ""}
  daemon -> host   {"cmd": "subscribe"}            on a second connection
  host -> daemon   {"type": "flow", "id": "<uuid>", "exe", "raddr", "rport", "host", "proto", "pid"}
                   a new connection the extension paused, waiting for the gate
"""
import asyncio
import json
import logging
import os
import socket

log = logging.getLogger("citadel.host")


class HostBridge:
    def __init__(self, path):
        self.path = path
        self._n = 0

    def available(self):
        """Is the host app listening?"""
        if not os.path.exists(self.path):
            return False
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            s.connect(self.path)
            return True
        except OSError:
            return False
        finally:
            s.close()

    async def request(self, cmd, args=None, timeout=30):
        """-> (code, out, err), like running citadel-enforcer."""
        self._n += 1
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(self.path, limit=64 * 1024 * 1024), 3)
        except (OSError, asyncio.TimeoutError) as e:
            return 127, "", "Citadel host app not running: %s" % e
        try:
            writer.write((json.dumps({"id": self._n, "cmd": cmd, "args": args or {}}) + "\n").encode())
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), timeout)
            reply = json.loads(line) if line else {}
            return int(reply.get("code", 1)), str(reply.get("out", "")), str(reply.get("err", "") or ("" if reply else "no reply"))
        except (OSError, ValueError, asyncio.TimeoutError) as e:
            return 1, "", "host request failed: %s" % e
        finally:
            writer.close()

    async def events(self, on_event):
        """Paused flows from the extension, for the gate. Reconnects on its own."""
        while True:
            try:
                reader, writer = await asyncio.open_unix_connection(self.path, limit=16 * 1024 * 1024)
            except OSError:
                await asyncio.sleep(2)
                continue
            try:
                writer.write(b'{"cmd": "subscribe"}\n')
                await writer.drain()
                while True:
                    line = await reader.readline()
                    if not line:
                        break
                    try:
                        on_event(json.loads(line))
                    except ValueError:
                        continue
                    except Exception:
                        log.exception("host event failed")
            except OSError:
                pass
            finally:
                writer.close()
            await asyncio.sleep(2)


def file_payload(path):
    """The JSON a spec/kill file holds, for sending to the host."""
    with open(path) as f:
        return json.load(f)
