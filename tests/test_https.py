import json
import pathlib
import socket
import ssl

import httpx
import pytest
import websockets

from granian import Granian


@pytest.mark.asyncio
@pytest.mark.parametrize('server_tls', ['asgi', 'rsgi', 'wsgi'], indirect=True)
@pytest.mark.parametrize('runtime_mode', ['mt', 'st'])
@pytest.mark.parametrize(
    'tls_scope', [('tls1.2', ssl.TLSVersion.TLSv1_2, 'TLSv1.2'), ('tls1.3', ssl.TLSVersion.TLSv1_3, 'TLSv1.3')]
)
async def test_tls_protocol(server_tls, runtime_mode, tls_scope):
    tls_input, tls_max_proto, tls_expected = tls_scope

    async with server_tls(runtime_mode, ws=False, tls_proto=tls_input) as port:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.maximum_version = tls_max_proto

        with socket.create_connection(('localhost', port)) as sock:
            with context.wrap_socket(sock, server_hostname='localhost') as ssock:
                tls_version = ssock.version()

        assert tls_version == tls_expected


@pytest.mark.asyncio
@pytest.mark.parametrize('server_tls', ['asgi', 'rsgi', 'wsgi'], indirect=True)
@pytest.mark.parametrize('runtime_mode', ['mt', 'st'])
async def test_http_scope(server_tls, runtime_mode):
    async with server_tls(runtime_mode, ws=False) as port:
        res = httpx.get(f'https://localhost:{port}/info?test=true', verify=False)

    assert res.status_code == 200
    data = res.json()
    assert data['scheme'] == 'https'


@pytest.mark.asyncio
@pytest.mark.parametrize('runtime_mode', ['mt', 'st'])
async def test_asgi_ws_scope(asgi_server, runtime_mode):
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    localhost_pem = pathlib.Path.cwd() / 'tests' / 'fixtures' / 'tls' / 'cert.pem'
    ssl_context.load_verify_locations(str(localhost_pem))

    async with asgi_server(runtime_mode, tls=True) as port:
        async with websockets.connect(f'wss://localhost:{port}/ws_info?test=true', ssl=ssl_context) as ws:
            res = await ws.recv()

    data = json.loads(res)
    assert data['scheme'] == 'wss'


@pytest.mark.asyncio
@pytest.mark.parametrize('runtime_mode', ['mt', 'st'])
async def test_rsgi_ws_scope(rsgi_server, runtime_mode):
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    localhost_pem = pathlib.Path.cwd() / 'tests' / 'fixtures' / 'tls' / 'cert.pem'
    ssl_context.load_verify_locations(str(localhost_pem))

    async with rsgi_server(runtime_mode, tls=True) as port:
        async with websockets.connect(f'wss://localhost:{port}/ws_info?test=true', ssl=ssl_context) as ws:
            res = await ws.recv()

    data = json.loads(res)
    assert data['scheme'] == 'https'


@pytest.mark.asyncio
async def test_tls_encrypted_key(rsgi_server):
    async with rsgi_server('st', ws=False, tls='priv') as port:
        res = httpx.get(f'https://localhost:{port}/info?test=true', verify=False)

    assert res.status_code == 200
    data = res.json()
    assert data['scheme'] == 'https'


@pytest.mark.asyncio
@pytest.mark.parametrize('runtime_mode', ['mt', 'st'])
async def test_asgi_tls_extension_scope(asgi_server, runtime_mode):
    async with asgi_server(runtime_mode, tls=True, ws=False) as port:
        res = httpx.get(f'https://localhost:{port}/info?test=true', verify=False)

    assert res.status_code == 200
    data = res.json()
    tls_ext = data['extensions']['tls']
    assert '-----BEGIN CERTIFICATE-----' in tls_ext['server_cert']
    assert isinstance(tls_ext['tls_version'], int)
    assert tls_ext['tls_version'] >= 0x0303
    assert isinstance(tls_ext['cipher_suite'], int)
    assert tls_ext['client_cert_chain'] == []
    assert tls_ext['client_cert_name'] is None
    assert tls_ext['client_cert_error'] is None


@pytest.mark.asyncio
@pytest.mark.parametrize('runtime_mode', ['mt', 'st'])
async def test_asgi_tls_extension_ws_scope(asgi_server, runtime_mode):
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    async with asgi_server(runtime_mode, tls=True) as port:
        async with websockets.connect(f'wss://localhost:{port}/ws_info?test=true', ssl=ssl_context) as ws:
            res = await ws.recv()

    data = json.loads(res)
    tls_ext = data['extensions']['tls']
    assert '-----BEGIN CERTIFICATE-----' in tls_ext['server_cert']
    assert isinstance(tls_ext['tls_version'], int)
    assert isinstance(tls_ext['cipher_suite'], int)


@pytest.mark.asyncio
@pytest.mark.parametrize('runtime_mode', ['mt', 'st'])
async def test_asgi_mtls_extension_scope(asgi_server, runtime_mode):
    certs_path = pathlib.Path.cwd() / 'tests' / 'fixtures' / 'tls'
    client_cert = (str(certs_path / 'client.pem'), str(certs_path / 'client-key.pem'))

    async with asgi_server(runtime_mode, tls=True, ws=False, tls_client_verify=True) as port:
        with httpx.Client(verify=False, cert=client_cert) as client:
            res = client.get(f'https://localhost:{port}/info?test=true')

    assert res.status_code == 200
    data = res.json()
    tls_ext = data['extensions']['tls']
    assert len(tls_ext['client_cert_chain']) >= 1
    assert '-----BEGIN CERTIFICATE-----' in tls_ext['client_cert_chain'][0]
    assert tls_ext['client_cert_name'] is not None
    assert 'CN=Test Client' in tls_ext['client_cert_name']


@pytest.mark.asyncio
@pytest.mark.parametrize('server', ['asgi'], indirect=True)
@pytest.mark.parametrize('runtime_mode', ['mt', 'st'])
async def test_no_tls_extension_plain(server, runtime_mode):
    async with server(runtime_mode, ws=False) as port:
        res = httpx.get(f'http://localhost:{port}/info?test=true')

    assert res.status_code == 200
    data = res.json()
    assert 'tls' not in data['extensions']


def test_ssl_client_verify_requires_ca():
    from granian.errors import ConfigurationError

    certs_path = pathlib.Path.cwd() / 'tests' / 'fixtures' / 'tls'
    with pytest.raises(ConfigurationError):
        Granian(
            'tests.apps.asgi:app',
            interface='asgi',
            ssl_cert=certs_path / 'cert.pem',
            ssl_key=certs_path / 'key.pem',
            ssl_client_verify=True,
        )
