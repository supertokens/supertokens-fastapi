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


from supertokens_fastapi.exceptions import (
    raise_try_refresh_token_exception,
    raise_unauthorised_exception,
    SuperTokensTokenTheftError,
    SuperTokensUnauthorisedError,
    SuperTokensTryRefreshTokenError,
    raise_general_exception
)
from supertokens_fastapi.handshake_info import HandshakeInfo
from supertokens_fastapi.session import Session
from supertokens_fastapi import session_helper
from supertokens_fastapi.cookie_and_header import (
    CookieConfig,
    clear_cookies,
    get_anti_csrf_header,
    attach_anti_csrf_header,
    set_options_api_headers,
    get_access_token_from_cookie,
    attach_access_token_to_cookie,
    get_refresh_token_from_cookie,
    attach_refresh_token_to_cookie,
    save_frontend_info_from_request,
    get_id_refresh_token_from_cookie,
    attach_id_refresh_token_to_cookie_and_header,
    get_cors_allowed_headers as get_cors_allowed_headers_from_cookie_and_headers
)
from supertokens_fastapi.default_callbacks import (
    default_unauthorised_callback,
    default_try_refresh_token_callback,
    default_token_theft_detected_callback
)
from fastapi.requests import Request
from fastapi.responses import Response, JSONResponse
from fastapi import FastAPI, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Callable, List, Union, Awaitable
from httpx import AsyncClient
from jwt import decode


async def create_new_session(request: Request, user_id: str, jwt_payload: Union[dict, None] = None,
                             session_data: Union[dict, None] = None) -> Session:
    session = await session_helper.create_new_session(user_id, jwt_payload, session_data)
    access_token = session['accessToken']
    refresh_token = session['refreshToken']
    id_refresh_token = session['idRefreshToken']
    request.state.supertokens = Session(access_token['token'], session['session']['handle'],
                                        session['session']['userId'], session['session']['userDataInJWT'])
    request.state.supertokens.new_access_token_info = access_token
    request.state.supertokens.new_refresh_token_info = refresh_token
    request.state.supertokens.new_id_refresh_token_info = id_refresh_token
    if 'antiCsrfToken' in session and session['antiCsrfToken'] is not None:
        request.state.supertokens.new_anti_csrf_token = session['antiCsrfToken']
    return request.state.supertokens


async def get_session(request: Request, enable_csrf_protection: bool) -> Session:
    save_frontend_info_from_request(request)
    id_refresh_token = get_id_refresh_token_from_cookie(request)
    if id_refresh_token is None:
        raise_unauthorised_exception('id refresh token is missing in cookies')
    access_token = get_access_token_from_cookie(request)
    if access_token is None:
        raise_try_refresh_token_exception('access token missing in cookies')
    anti_csrf_token = get_anti_csrf_header(request)
    new_session = await session_helper.get_session(access_token, anti_csrf_token, enable_csrf_protection)
    if 'accessToken' in new_session:
        access_token = new_session['accessToken']['token']

    request.state.supertokens = Session(access_token, new_session['session']['handle'],
                                        new_session['session']['userId'], new_session['session']['userDataInJWT'])

    if 'accessToken' in new_session:
        request.state.supertokens.new_access_token_info = new_session['accessToken']
    return request.state.supertokens


async def refresh_session(request: Request) -> Session:
    save_frontend_info_from_request(request)
    refresh_token = get_refresh_token_from_cookie(request)
    if refresh_token is None:
        raise_unauthorised_exception('Missing auth tokens in cookies. Have you set the correct refresh API path in '
                                     'your frontend and SuperTokens config?')
    anti_csrf_token = get_anti_csrf_header(request)
    new_session = await session_helper.refresh_session(refresh_token, anti_csrf_token)
    access_token = new_session['accessToken']
    refresh_token = new_session['refreshToken']
    id_refresh_token = new_session['idRefreshToken']
    request.state.supertokens = Session(access_token['token'], new_session['session']['handle'],
                                        new_session['session']['userId'], new_session['session']['userDataInJWT'])
    request.state.supertokens.new_access_token_info = access_token
    request.state.supertokens.new_refresh_token_info = refresh_token
    request.state.supertokens.new_id_refresh_token_info = id_refresh_token
    if 'antiCsrfToken' in new_session and new_session['antiCsrfToken'] is not None:
        request.state.supertokens.new_anti_csrf_token = new_session['antiCsrfToken']
    return request.state.supertokens


async def revoke_session(session_handle: str) -> bool:
    return await session_helper.revoke_session(session_handle)


async def revoke_all_sessions_for_user(user_id: str) -> List[str]:
    return await session_helper.revoke_all_sessions_for_user(user_id)


async def get_all_session_handles_for_user(user_id: str) -> List[str]:
    return await session_helper.get_all_session_handles_for_user(user_id)


async def revoke_multiple_sessions(session_handles: List[str]) -> List[str]:
    return await session_helper.revoke_multiple_sessions(session_handles)


async def get_session_data(session_handle: str) -> dict:
    return await session_helper.get_session_data(session_handle)


async def update_session_data(session_handle: str, new_session_data: dict) -> None:
    await session_helper.update_session_data(session_handle, new_session_data)


async def get_jwt_payload(session_handle: str) -> dict:
    return await session_helper.get_jwt_payload(session_handle)


async def update_jwt_payload(session_handle: str, new_jwt_payload: dict) -> None:
    await session_helper.update_jwt_payload(session_handle, new_jwt_payload)


def set_relevant_headers_for_options_api(response: Response) -> None:
    set_options_api_headers(response)


def get_cors_allowed_headers():
    return get_cors_allowed_headers_from_cookie_and_headers()


async def __supertokens_session(request: Request, enable_anti_csrf_check: bool) -> Session:
    refresh_path = (await HandshakeInfo.get_instance()).refresh_token_path
    if CookieConfig.get_instance().refresh_token_path is not None:
        refresh_path = CookieConfig.get_instance().refresh_token_path
    if request.url.path in (refresh_path, refresh_path + '/',
                            '/' + refresh_path + '/' + refresh_path + '/') and request.method == "POST":
        request.state.supertokens = await refresh_session(request)
    else:
        request.state.supertokens = await get_session(request, enable_anti_csrf_check)
    return request.state.supertokens


async def supertokens_session(request: Request):
    enable_anti_csrf_check = request.method != "GET"
    return await __supertokens_session(request, enable_anti_csrf_check)


async def supertokens_session_with_anti_csrf(request: Request):
    return await __supertokens_session(request, True)


async def supertokens_session_without_anti_csrf(request: Request):
    return await __supertokens_session(request, False)


async def auth0_handler(
    request: Request,
    domain: str,
    client_id: str,
    client_secret: str,
    callback: Union[Callable[[str, str, str, Union[str, None]], Awaitable[any]], None] = None
) -> Response:
    try:
        request_json = await request.json()
        action = request_json['action']
        if action == 'logout':
            if not hasattr(request.state, 'supertokens'):
                request.state.supertokens = await __supertokens_session(request, True)
            await request.state.supertokens.revoke_session()
            return JSONResponse({})
        auth_code = None
        if 'code' in request_json:
            auth_code = request_json['code']
        is_login = action == 'login'
        if not is_login:
            request.state.supertokens = await __supertokens_session(request, True)

        form_data = {}
        if auth_code is None and action == 'refresh':
            session_data = await request.state.supertokens.get_session_data()
            if 'refresh_token' not in session_data:
                return JSONResponse(content={}, status_code=403)
            form_data = {
                'grant_type': 'refresh_token',
                'client_id': client_id,
                'client_secret': client_secret,
                'refresh_token': session_data['refresh_token']
            }
        else:
            form_data = {
                'grant_type': 'authorization_code',
                'client_id': client_id,
                'client_secret': client_secret,
                'code': auth_code,
                'redirect_uri': request_json['redirect_uri']
            }

        response = await AsyncClient().post(
            url='https://' + domain + '/oauth/token',
            data=form_data,
            headers={
                'content-type': 'application/x-www-form-urlencoded'
            }
        )
        if response.status_code != 200:
            return JSONResponse(content={}, status_code=response.status_code)
        response_json = response.json()
        id_token = response_json['id_token']
        expires_in = response_json['expires_in']
        access_token = response_json['access_token']
        refresh_token = None
        if 'refresh_token' in response_json:
            refresh_token = response_json['refresh_token']

        if is_login:
            payload = decode(jwt=id_token, verify=False)
            if callback is not None:
                try:
                    await callback(payload['sub'], id_token, access_token, refresh_token)
                except TypeError:
                    callback(payload['sub'], id_token, access_token, refresh_token)
            else:
                session_data = {}
                if refresh_token is not None:
                    session_data['refresh_token'] = refresh_token
                await create_new_session(request, payload['sub'], {}, session_data)
        elif auth_code is not None:
            session_data = await request.state.supertokens.get_session_data()
            if refresh_token is not None:
                session_data['refresh_token'] = refresh_token
            elif 'refresh_token' in session_data:
                del session_data['refresh_token']
            await request.state.supertokens.update_session_data(session_data)
        return JSONResponse(content={
            'id_token': id_token,
            'expires_in': expires_in
        })
    except HTTPException as e:
        # if the exception is of type HTTPException, we don't modify the exception and raise it as it is
        raise e
    except Exception as err:
        raise_general_exception(err)


async def manage_cookies_post_response(session: Session, response: Response):
    if session.remove_cookies:
        await clear_cookies(response)
    else:
        access_token = session.new_access_token_info
        if access_token is not None:
            await attach_access_token_to_cookie(
                response,
                access_token['token'],
                access_token['expiry'],
                access_token['domain'] if 'domain' in access_token else None,
                access_token['cookiePath'],
                access_token['cookieSecure'],
                access_token['sameSite']
            )
        refresh_token = session.new_refresh_token_info
        if refresh_token is not None:
            await attach_refresh_token_to_cookie(
                response,
                refresh_token['token'],
                refresh_token['expiry'],
                refresh_token['domain'] if 'domain' in refresh_token else None,
                refresh_token['cookiePath'],
                refresh_token['cookieSecure'],
                refresh_token['sameSite']
            )
        id_refresh_token = session.new_id_refresh_token_info
        if id_refresh_token is not None:
            await attach_id_refresh_token_to_cookie_and_header(
                response,
                id_refresh_token['token'],
                id_refresh_token['expiry'],
                id_refresh_token['domain'] if 'domain' in id_refresh_token else None,
                id_refresh_token['cookiePath'],
                id_refresh_token['cookieSecure'],
                id_refresh_token['sameSite']
            )
        anti_csrf_token = session.new_anti_csrf_token
        if anti_csrf_token is not None:
            attach_anti_csrf_header(response, anti_csrf_token)


class SupertokensResponseMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        if hasattr(request.state, "supertokens") and isinstance(request.state.supertokens, Session):
            await manage_cookies_post_response(request.state.supertokens, response)
        return response


class SuperTokens:
    def __init__(
        self,
        app: FastAPI,
        hosts=None,
        api_key=None,
        access_token_path=None,
        refresh_token_path=None,
        cookie_domain=None,
        cookie_secure=None,
        cookie_same_site=None
    ):
        self.__unauthorised_callback = default_unauthorised_callback
        self.__try_refresh_token_callback = default_try_refresh_token_callback
        self.__token_theft_detected_callback = default_token_theft_detected_callback

        session_helper.init(hosts, api_key)
        CookieConfig.init(access_token_path, refresh_token_path, cookie_domain, cookie_secure, cookie_same_site)
        app.add_middleware(SupertokensResponseMiddleware)
        self.__set_error_handler_callbacks(app)

    def __set_error_handler_callbacks(self, app):
        @app.exception_handler(SuperTokensUnauthorisedError)
        async def handle_unauthorised(_, e):
            try:
                response = await self.__unauthorised_callback(e)
            except TypeError:
                response = self.__unauthorised_callback(e)
            await clear_cookies(response)
            return response

        @app.exception_handler(SuperTokensTryRefreshTokenError)
        async def handle_try_refresh_token(_, e):
            try:
                response = await self.__try_refresh_token_callback(e)
            except TypeError:
                response = self.__try_refresh_token_callback(e)
            return response

        @app.exception_handler(SuperTokensTokenTheftError)
        async def handle_token_theft(_, e):
            try:
                response = await self.__token_theft_detected_callback(e.session_handle, e.user_id)
            except TypeError:
                response = self.__token_theft_detected_callback(e.session_handle, e.user_id)
            await clear_cookies(response)
            return response

    def set_unauthorised_error_handler(self, callback: Callable[[SuperTokensUnauthorisedError], Union[Awaitable[Response], Response]]):
        self.__unauthorised_callback = callback

    def set_try_refresh_token_error_handler(self, callback: Callable[[SuperTokensTryRefreshTokenError],
                                                                     Union[Awaitable[Response], Response]]):
        self.__try_refresh_token_callback = callback

    def set_token_theft_detected_error_handler(self, callback: Callable[[str, str], Awaitable[Response]]):
        self.__token_theft_detected_callback = callback
