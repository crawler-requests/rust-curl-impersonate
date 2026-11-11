"""Capture Python client fingerprints (HTTP/1.1 unless the client does h2)."""
import sys

URL = "https://tls.peet.ws/api/all"


def save(path, body):
    with open(path, "wb") as fh:
        fh.write(body)


def requests_capture(path):
    import requests

    response = requests.get(URL, timeout=20)
    response.raise_for_status()
    save(path, response.content)
    print(f"requests {requests.__version__}: {response.status_code}")


def httpx_capture(path):
    import httpx

    with httpx.Client(http2=True, timeout=20) as client:
        response = client.get(URL)
        response.raise_for_status()
        save(path, response.content)
        print(f"httpx {httpx.__version__}: {response.http_version} {response.status_code}")


def urllib_capture(path):
    import urllib.request

    with urllib.request.urlopen(URL, timeout=20) as response:
        save(path, response.read())
        print(f"urllib: {response.status} {response.version}")


def httpclient_capture(path):
    import http.client

    conn = http.client.HTTPSConnection("tls.peet.ws", timeout=20)
    conn.request("GET", "/api/all")
    response = conn.getresponse()
    save(path, response.read())
    print(f"http.client: {response.status} {response.version}")
    conn.close()


def aiohttp_capture(path):
    import asyncio

    import aiohttp

    async def run():
        async with aiohttp.ClientSession() as session:
            async with session.get(URL, timeout=aiohttp.ClientTimeout(total=20)) as response:
                save(path, await response.read())
                print(f"aiohttp {aiohttp.__version__}: {response.status}")

    asyncio.run(run())


MODES = {
    "requests": requests_capture,
    "httpx": httpx_capture,
    "urllib": urllib_capture,
    "aiohttp": aiohttp_capture,
    "httpclient": httpclient_capture,
}

if __name__ == "__main__":
    mode, out = sys.argv[1], sys.argv[2]
    MODES[mode](out)
