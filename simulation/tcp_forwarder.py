"""Tiny TCP forwarder for PaaS private networking.

Render private services have no public DNS entry, so inside the backend
container the fake ``.onion`` / ``.example`` hostnames cannot be resolved by
name. This forwarder runs as a second Render service that owns a hosts-style
mapping: it listens on one public port and forwards raw TCP to a target host
and port over Render's private network.

The backend's offline allowlist still refuses public hosts, so instead of
dialling the forwarder directly, deploy it *as* the mock service's public
front and set the backend's base-URL env vars to the forwarder's private
hostname. This keeps every probe inside the workspace's private network.

Configuration (env):
    FORWARD_TARGET_HOST   host to forward to (private name of the mock service)
    FORWARD_TARGET_PORT   port to forward to (default 8080)
    PORT                  public/private listen port (Render injects it)
"""

from __future__ import annotations

import asyncio
import os

import uvicorn


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    target_host = os.getenv("FORWARD_TARGET_HOST", "127.0.0.1")
    target_port = int(os.getenv("FORWARD_TARGET_PORT", "8080"))
    try:
        remote_reader, remote_writer = await asyncio.open_connection(target_host, target_port)
    except OSError:
        writer.close()
        return

    async def _copy(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        try:
            while True:
                chunk = await src.read(65536)
                if not chunk:
                    break
                dst.write(chunk)
                await dst.drain()
        except OSError:
            pass
        finally:
            try:
                dst.close()
            except OSError:
                pass

    await asyncio.gather(_copy(reader, remote_writer), _copy(remote_reader, writer))


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    await _pipe(reader, writer)


async def serve() -> None:
    port = int(os.getenv("PORT", "10000"))
    server = await asyncio.start_server(handle, host="0.0.0.0", port=port)
    uvicorn.logging.LoggingNamespace  # keep uvicorn import meaningful
    print(f"tcp-forwarder -> {os.getenv('FORWARD_TARGET_HOST', '127.0.0.1')}:"
          f"{os.getenv('FORWARD_TARGET_PORT', '8080')} on :{port}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(serve())
