"""citadel.proxy's host name choice, against fake SOCKS5 and HTTP proxies on loopback."""
import asyncio
import ipaddress
import os
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from citadel import proxy as PX  # noqa: E402

DST = ("93.184.215.14", 80)
REQUEST = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"


class HostName(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.targets, self.events = [], []
        saved = (PX.sink, PX.check_name, PX.verified_name)
        PX.sink = self.events.append

        def restore():
            PX.sink, PX.check_name, PX.verified_name = saved
        self.addCleanup(restore)
        self.socks = await asyncio.start_server(self.fake_socks5, "127.0.0.1", 0)
        self.http = await asyncio.start_server(self.fake_http, "127.0.0.1", 0)
        for srv in (self.socks, self.http):
            self.addAsyncCleanup(self._close, srv)

    @staticmethod
    async def _close(srv):
        srv.close()
        await srv.wait_closed()

    async def fake_socks5(self, r, w):
        await r.readexactly(3)                 # no login
        w.write(b"\x05\x00")
        atyp = (await r.readexactly(4))[3]
        if atyp == 3:
            addr = (await r.readexactly((await r.readexactly(1))[0])).decode()
        else:
            addr = str(ipaddress.ip_address(await r.readexactly(4 if atyp == 1 else 16)))
        self.targets.append((addr, struct.unpack("!H", await r.readexactly(2))[0]))
        w.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
        await w.drain()
        w.write(await r.read(65536))           # echo the app's first bytes
        await w.drain()
        w.close()

    async def fake_http(self, r, w):
        head = await r.readuntil(b"\r\n\r\n")
        host, port = head.split(b"\r\n", 1)[0].split()[1].decode().rsplit(":", 1)
        self.targets.append((host, int(port)))
        w.write(b"HTTP/1.1 200 OK\r\n\r\n")
        await w.drain()
        w.write(await r.read(65536))
        await w.drain()
        w.close()

    async def run_app(self, srv, kind, payload=REQUEST):
        """An app connection redirected to the proxy listener; -> what came back."""
        px = {"type": kind, "host": "127.0.0.1", "port": srv.sockets[0].getsockname()[1]}

        async def listener(r, w):
            PX.live[w] = None                  # as make_handler does
            try:
                await PX._serve(px, "p1", DST[0], DST[1], r, w)
            finally:
                PX.live.pop(w, None)
        lsrv = await asyncio.start_server(listener, "127.0.0.1", 0)
        try:
            r, w = await asyncio.open_connection("127.0.0.1", lsrv.sockets[0].getsockname()[1])
            self.app_port = w.get_extra_info("sockname")[1]
            w.write(payload)
            await w.drain()
            try:
                return await asyncio.wait_for(r.read(65536), 5)
            except ConnectionResetError:
                return b""
            finally:
                w.close()
        finally:
            lsrv.close()

    async def test_name_goes_to_the_proxy_when_allowed(self):
        asked = []

        async def check(lport, ip, port, name):
            asked.append((lport, ip, port, name))
            return True

        async def no_local_lookup(name, ip):
            raise AssertionError("resolved here")
        PX.check_name, PX.verified_name = check, no_local_lookup
        for srv, kind in ((self.socks, "socks5"), (self.http, "http")):
            self.assertEqual(await self.run_app(srv, kind), REQUEST)
            self.assertEqual(self.targets[-1], ("example.com", 80))
            self.assertEqual(asked[-1], (self.app_port, DST[0], DST[1], "example.com"))

    async def test_denied_name_resets_without_reaching_the_proxy(self):
        async def check(lport, ip, port, name):
            return False
        PX.check_name = check
        self.assertEqual(await self.run_app(self.socks, "socks5"), b"")
        self.assertEqual(self.targets, [])

    async def test_no_name_goes_to_the_address(self):
        async def check(lport, ip, port, name):
            raise AssertionError("nothing to check")
        PX.check_name = check
        self.assertEqual(await self.run_app(self.socks, "socks5", b"\x00binary"), b"\x00binary")
        self.assertEqual(self.targets, [DST])

    async def test_option_off_needs_the_name_to_resolve_here(self):
        async def elsewhere(name, ip):
            return None                        # example.com doesn't resolve to DST here
        PX.verified_name = elsewhere
        self.assertEqual(await self.run_app(self.socks, "socks5"), REQUEST)
        self.assertEqual(self.targets, [DST])


if __name__ == "__main__":
    unittest.main()
