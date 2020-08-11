"""
Copyright (c) 2020, VRAI Labs and/or its affiliates. All rights reserved.

This software is licensed under the Apache License, Version 2.0 (the
"License") as published by the Apache Software Foundation.

You may not use this file except in compliance with the License. You may
obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

import nest_asyncio
import respx
from fastapi import FastAPI, Depends, HTTPException
from fastapi.requests import Request
from fastapi.testclient import TestClient
from fastapi.responses import JSONResponse
from jwt import DecodeError
from pytest import fixture, mark
from .utils import (
    get_unix_timestamp, reset, clean_st,
    setup_st, start_st, verify_within_5_second_diff,
    AUTH0_DOMAIN,
    AUTH0_CLIENT_ID,
    AUTH0_CLIENT_SECRET,
    TEST_ID_TOKEN,
    extract_all_cookies
)
from supertokens_fastapi.supertokens import (
    auth0_handler,
    create_new_session,
    SuperTokens,
    Session,
    supertokens_session
)
from supertokens_fastapi.utils import get_timestamp_ms
from supertokens_fastapi.constants import (
    API_VERSION,
    SESSION,
    SESSION_REMOVE,
    SESSION_DATA,
    HANDSHAKE
)
import httpx
import json
from requests import post, get

nest_asyncio.apply()


def setup_function(f):
    reset()
    clean_st()
    setup_st()


def teardown_function(f):
    reset()
    clean_st()


@fixture(scope='function')
def client():
    app = FastAPI()
    SuperTokens(app)

    @app.exception_handler(DecodeError)
    async def validation_exception_handler(_, __):
        return JSONResponse(status_code=500, content={'err': 'json decode error'})

    @app.post("/login-without-callback")
    async def login_without_callback(request: Request):
        return await auth0_handler(request, AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET)

    @app.post("/login-with-callback-save-rt")
    async def login_with_callback_save_rt(request: Request):
        async def callback(user_id: str, __: str, access_token: str, refresh_token: str):
            await create_new_session(request, user_id, {}, {
                'access_token': access_token,
                'refresh_token': refresh_token
            })

        return await auth0_handler(request, AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET, callback)

    @app.post("/login-with-callback")
    async def login_with_callback(request: Request):
        async def callback(user_id: str, __: str, _: str, ___: str):
            await create_new_session(request, user_id, {}, {})

        return await auth0_handler(request, AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET, callback)

    @app.post("/login-with-error-callback")
    async def login_with_error_callback(request: Request):
        async def callback(_: str, __: str, access_token: str, ___: str):
            if access_token == 'test-access-token':
                raise HTTPException(status_code=500, detail='access token not matching')

        return await auth0_handler(request, AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET, callback)

    @app.get("/get-session-data")
    async def get_session_data(session: Session = Depends(supertokens_session)):
        return JSONResponse(await session.get_session_data())

    @app.post("/logout-with-depends")
    async def logout_with_depends(request: Request, _: Session = Depends(supertokens_session)):
        return await auth0_handler(request, AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET)

    @app.post("/logout-without-depends")
    async def logout_without_depends(request: Request):
        return await auth0_handler(request, AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET)

    @app.post("/refresh-auth0")
    async def refresh_auth0(request: Request):
        return await auth0_handler(request, AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET)

    return TestClient(app)


def request_mock():
    mock = respx.mock(assert_all_mocked=False, assert_all_called=False)

    get_apis = [
        'http://localhost:3567' + API_VERSION,
        'http://localhost:3567' + SESSION_DATA
    ]

    post_apis = [
        'http://localhost:3567' + SESSION,
        'http://localhost:3567' + HANDSHAKE,
        'http://localhost:3567' + SESSION_REMOVE
    ]

    def mock_get(request: httpx.Request, response):
        url = str(request.url).split('?')[0]
        if url not in get_apis or request.method != 'GET':
            return None
        res = get(url=request.url, headers=request.headers)
        response.content = json.loads(res.content.decode('utf-8'))
        response.status_code = res.status_code
        return response

    def mock_post(request: httpx.Request, response):
        url = str(request.url).split('?')[0]
        if url not in post_apis or request.method != 'POST':
            return None
        data = json.loads(request.read().decode())
        res = post(url=request.url, json=data, headers=request.headers)
        response.content = json.loads(res.content.decode('utf-8'))
        response.status_code = res.status_code
        return response

    mock.add(mock_get)
    mock.add(mock_post)
    return mock


@mark.asyncio
async def test_login_without_callback(client: TestClient):
    async with request_mock() as mock:
        start_st()
        mock.post(
            url='https://' + AUTH0_DOMAIN + '/oauth/token',
            status_code=200,
            content={
                'id_token': TEST_ID_TOKEN,
                'expires_in': get_timestamp_ms() + 30000,
                'access_token': 'test-access-token',
                'refresh_token': 'test-refresh-token'
            }
        )
        r = client.post("/login-without-callback", json={
            'action': 'login',
            'redirect_uri': 'http://localhost:3000',
            'code': 'randomString'
        })
        assert r.json()['id_token'] == TEST_ID_TOKEN


@mark.asyncio
async def test_login_with_callback(client: TestClient):
    async with request_mock() as mock:
        start_st()
        mock.post(
            url='https://' + AUTH0_DOMAIN + '/oauth/token',
            status_code=200,
            content={
                'id_token': TEST_ID_TOKEN,
                'expires_in': get_timestamp_ms() + 30000,
                'access_token': 'test-access-token',
                'refresh_token': 'test-refresh-token'
            }
        )
        r1 = client.post("/login-with-callback-save-rt", json={
            'action': 'login',
            'redirect_uri': 'http://localhost:3000',
            'code': 'randomString'
        })
        c1 = extract_all_cookies(r1)
        r2 = client.get(
            url="/get-session-data",
            cookies={
                'sAccessToken': c1['sAccessToken']['value'],
                'sIdRefreshToken': c1['sIdRefreshToken']['value']
            }
        )
        assert r2.json() == {
            'access_token': 'test-access-token',
            'refresh_token': 'test-refresh-token'
        }


@mark.asyncio
async def test_login_with_callback_error_thrown(client: TestClient):
    async with request_mock() as mock:
        start_st()
        mock.post(
            url='https://' + AUTH0_DOMAIN + '/oauth/token',
            status_code=200,
            content={
                'id_token': TEST_ID_TOKEN,
                'expires_in': get_timestamp_ms() + 30000,
                'access_token': 'test-access-token',
                'refresh_token': 'test-refresh-token'
            }
        )
        r1 = client.post("/login-with-error-callback", json={
            'action': 'login',
            'redirect_uri': 'http://localhost:3000',
            'code': 'randomString'
        })
        assert r1.status_code == 500
        assert r1.json() == {
            'detail': 'access token not matching'
        }


@mark.asyncio
async def test_login_non_200_response(client: TestClient):
    async with request_mock() as mock:
        start_st()
        mock.post(
            url='https://' + AUTH0_DOMAIN + '/oauth/token',
            status_code=403,
            content={}
        )
        r1 = client.post("/login-without-callback", json={
            'action': 'login',
            'redirect_uri': 'http://localhost:3000',
            'code': 'randomString'
        })
        assert r1.status_code == 403


@mark.asyncio
async def test_login_invalid_id_token(client: TestClient):
    async with request_mock() as mock:
        start_st()
        mock.post(
            url='https://' + AUTH0_DOMAIN + '/oauth/token',
            status_code=200,
            content={
                'id_token': 'invalid token',
                'expires_in': get_timestamp_ms() + 30000,
                'access_token': 'test-access-token',
                'refresh_token': 'test-refresh-token'
            }
        )
        r1 = client.post("/login-without-callback", json={
            'action': 'login',
            'redirect_uri': 'http://localhost:3000',
            'code': 'randomString'
        })
        assert r1.status_code == 500


@mark.asyncio
async def test_logout_with_depends(client: TestClient):
    async with request_mock() as mock:
        start_st()
        mock.post(
            url='https://' + AUTH0_DOMAIN + '/oauth/token',
            status_code=200,
            content={
                'id_token': TEST_ID_TOKEN,
                'expires_in': get_timestamp_ms() + 30000,
                'access_token': 'test-access-token',
                'refresh_token': 'test-refresh-token'
            }
        )
        r1 = client.post("/login-without-callback", json={
            'action': 'login',
            'redirect_uri': 'http://localhost:3000',
            'code': 'randomString'
        })
        c1 = extract_all_cookies(r1)
        r2 = client.post(
            url="/logout-with-depends",
            cookies={
                'sAccessToken': c1['sAccessToken']['value'],
                'sIdRefreshToken': c1['sIdRefreshToken']['value']
            },
            headers={
                'anti-csrf': r1.headers.get('anti-csrf')
            },
            json={
                'action': 'logout'
            }
        )
        c2 = extract_all_cookies(r2)
        assert r2.headers.get('anti-csrf') is None
        assert c2['sAccessToken']['value'] == ''
        assert c2['sRefreshToken']['value'] == ''
        assert c2['sIdRefreshToken']['value'] == ''
        assert c2['sAccessToken']['domain'] == 'localhost'
        assert c2['sRefreshToken']['domain'] == 'localhost'
        assert c2['sIdRefreshToken']['domain'] == 'localhost'
        assert c2['sAccessToken']['path'] == '/'
        assert c2['sRefreshToken']['path'] == '/refresh'
        assert c2['sIdRefreshToken']['path'] == '/'
        assert c2['sAccessToken']['httponly']
        assert c2['sRefreshToken']['httponly']
        assert c2['sIdRefreshToken']['httponly']
        assert c2['sAccessToken']['samesite'] == 'none'
        assert c2['sRefreshToken']['samesite'] == 'none'
        assert c2['sIdRefreshToken']['samesite'] == 'none'
        assert c2['sAccessToken']['secure'] is None
        assert c2['sRefreshToken']['secure'] is None
        assert c2['sIdRefreshToken']['secure'] is None
        assert verify_within_5_second_diff(
            get_unix_timestamp(c2['sAccessToken']['expires']), 0
        )
        assert verify_within_5_second_diff(
            get_unix_timestamp(c2['sRefreshToken']['expires']), 0
        )
        assert verify_within_5_second_diff(
            get_unix_timestamp(c2['sIdRefreshToken']['expires']), 0
        )
        assert r2.headers['Id-Refresh-Token'] == 'remove'


@mark.asyncio
async def test_logout_without_depends(client: TestClient):
    async with request_mock() as mock:
        start_st()
        mock.post(
            url='https://' + AUTH0_DOMAIN + '/oauth/token',
            status_code=200,
            content={
                'id_token': TEST_ID_TOKEN,
                'expires_in': get_timestamp_ms() + 30000,
                'access_token': 'test-access-token',
                'refresh_token': 'test-refresh-token'
            }
        )
        r1 = client.post("/login-without-callback", json={
            'action': 'login',
            'redirect_uri': 'http://localhost:3000',
            'code': 'randomString'
        })
        c1 = extract_all_cookies(r1)
        r2 = client.post(
            url="/logout-without-depends",
            cookies={
                'sAccessToken': c1['sAccessToken']['value'],
                'sIdRefreshToken': c1['sIdRefreshToken']['value']
            },
            headers={
                'anti-csrf': r1.headers.get('anti-csrf')
            },
            json={
                'action': 'logout'
            }
        )
        c2 = extract_all_cookies(r2)
        assert r2.headers.get('anti-csrf') is None
        assert c2['sAccessToken']['value'] == ''
        assert c2['sRefreshToken']['value'] == ''
        assert c2['sIdRefreshToken']['value'] == ''
        assert c2['sAccessToken']['domain'] == 'localhost'
        assert c2['sRefreshToken']['domain'] == 'localhost'
        assert c2['sIdRefreshToken']['domain'] == 'localhost'
        assert c2['sAccessToken']['path'] == '/'
        assert c2['sRefreshToken']['path'] == '/refresh'
        assert c2['sIdRefreshToken']['path'] == '/'
        assert c2['sAccessToken']['httponly']
        assert c2['sRefreshToken']['httponly']
        assert c2['sIdRefreshToken']['httponly']
        assert c2['sAccessToken']['samesite'] == 'none'
        assert c2['sRefreshToken']['samesite'] == 'none'
        assert c2['sIdRefreshToken']['samesite'] == 'none'
        assert c2['sAccessToken']['secure'] is None
        assert c2['sRefreshToken']['secure'] is None
        assert c2['sIdRefreshToken']['secure'] is None
        assert verify_within_5_second_diff(
            get_unix_timestamp(c2['sAccessToken']['expires']), 0
        )
        assert verify_within_5_second_diff(
            get_unix_timestamp(c2['sRefreshToken']['expires']), 0
        )
        assert verify_within_5_second_diff(
            get_unix_timestamp(c2['sIdRefreshToken']['expires']), 0
        )
        assert r2.headers['Id-Refresh-Token'] == 'remove'


@mark.asyncio
async def test_refresh_with_session_data(client: TestClient):
    async with request_mock() as mock:
        start_st()
        mock.post(
            url='https://' + AUTH0_DOMAIN + '/oauth/token',
            status_code=200,
            content={
                'id_token': TEST_ID_TOKEN,
                'expires_in': get_timestamp_ms() + 30000,
                'access_token': 'test-access-token',
                'refresh_token': 'test-refresh-token'
            },
            alias='t1'
        )
        r1 = client.post("/login-without-callback", json={
            'action': 'login',
            'redirect_uri': 'http://localhost:3000',
            'code': 'randomString'
        })
        c1 = extract_all_cookies(r1)
        mock.pop('t1')
        mock.post(
            url='https://' + AUTH0_DOMAIN + '/oauth/token',
            status_code=200,
            content={
                'id_token': 'custom-token',
                'expires_in': get_timestamp_ms() + 30000,
                'access_token': 'test-access-token',
                'refresh_token': 'test-refresh-token'
            },
            alias='t2'
        )

        r2 = client.post(
            url="/refresh-auth0",
            cookies={
                'sAccessToken': c1['sAccessToken']['value'],
                'sIdRefreshToken': c1['sIdRefreshToken']['value']
            },
            headers={
                'anti-csrf': r1.headers.get('anti-csrf')
            },
            json={
                'action': 'refresh'
            }
        )
        assert r2.status_code == 200
        assert r2.json()['id_token'] == 'custom-token'


@mark.asyncio
async def test_refresh_without_session_data(client: TestClient):
    async with request_mock() as mock:
        start_st()
        mock.post(
            url='https://' + AUTH0_DOMAIN + '/oauth/token',
            status_code=200,
            content={
                'id_token': TEST_ID_TOKEN,
                'expires_in': get_timestamp_ms() + 30000,
                'access_token': 'test-access-token',
                'refresh_token': 'test-refresh-token'
            }
        )
        r1 = client.post("/login-with-callback", json={
            'action': 'login',
            'redirect_uri': 'http://localhost:3000',
            'code': 'randomString'
        })
        c1 = extract_all_cookies(r1)

        r2 = client.post(
            url="/refresh-auth0",
            cookies={
                'sAccessToken': c1['sAccessToken']['value'],
                'sIdRefreshToken': c1['sIdRefreshToken']['value']
            },
            headers={
                'anti-csrf': r1.headers.get('anti-csrf')
            },
            json={
                'action': 'refresh'
            }
        )
        assert r2.status_code == 403


@mark.asyncio
async def test_refresh_non_200_response(client: TestClient):
    async with request_mock() as mock:
        start_st()
        mock.post(
            url='https://' + AUTH0_DOMAIN + '/oauth/token',
            status_code=200,
            content={
                'id_token': TEST_ID_TOKEN,
                'expires_in': get_timestamp_ms() + 30000,
                'access_token': 'test-access-token',
                'refresh_token': 'test-refresh-token'
            },
            alias='t1'
        )
        r1 = client.post("/login-without-callback", json={
            'action': 'login',
            'redirect_uri': 'http://localhost:3000',
            'code': 'randomString'
        })
        c1 = extract_all_cookies(r1)
        mock.pop('t1')
        mock.post(
            url='https://' + AUTH0_DOMAIN + '/oauth/token',
            status_code=403,
            content={},
            alias='t2'
        )
        r2 = client.post(
            url="/refresh-auth0",
            cookies={
                'sAccessToken': c1['sAccessToken']['value'],
                'sIdRefreshToken': c1['sIdRefreshToken']['value']
            },
            headers={
                'anti-csrf': r1.headers.get('anti-csrf')
            },
            json={
                'action': 'refresh'
            }
        )
        assert r2.status_code == 403
