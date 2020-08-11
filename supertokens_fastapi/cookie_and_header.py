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

from supertokens_fastapi.constants import (
    ACCESS_TOKEN_COOKIE_KEY,
    REFRESH_TOKEN_COOKIE_KEY,
    ANTI_CSRF_HEADER_SET_KEY,
    ANTI_CSRF_HEADER_GET_KEY,
    ID_REFRESH_TOKEN_COOKIE_KEY,
    ACCESS_CONTROL_ALLOW_HEADERS,
    ACCESS_CONTROL_EXPOSE_HEADERS,
    ID_REFRESH_TOKEN_HEADER_SET_KEY,
    ACCESS_CONTROL_ALLOW_CREDENTIALS,
    SUPERTOKENS_SDK_NAME_HEADER_GET_KEY,
    SUPERTOKENS_SDK_NAME_HEADER_SET_KEY,
    SUPERTOKENS_SDK_VERSION_HEADER_GET_KEY,
    SUPERTOKENS_SDK_VERSION_HEADER_SET_KEY
)
from supertokens_fastapi.device_info import DeviceInfo
from supertokens_fastapi.exceptions import raise_general_exception
from supertokens_fastapi.handshake_info import HandshakeInfo
from urllib.parse import quote, unquote
from os import environ
from fastapi.requests import Request
from fastapi.responses import Response
from supertokens_fastapi.utils import get_timestamp_ms


class CookieConfig:
    __instance = None

    def __init__(self, access_token_path=None, refresh_token_path=None, cookie_domain=None, cookie_secure=None,
                 cookie_same_site=None):
        self.access_token_path = access_token_path if isinstance(access_token_path, str) else None
        self.refresh_token_path = refresh_token_path if isinstance(refresh_token_path, str) else None
        self.cookie_domain = cookie_domain if isinstance(cookie_domain, str) else None
        self.cookie_secure = cookie_secure if isinstance(cookie_secure, bool) else None
        self.cookie_same_site = cookie_same_site if isinstance(cookie_same_site, str) else None

    @staticmethod
    def get_instance():
        if CookieConfig.__instance is None:
            CookieConfig.__instance = CookieConfig()
        return CookieConfig.__instance

    @staticmethod
    def init(access_token_path, refresh_token_path, cookie_domain, cookie_secure, cookie_same_site):
        if CookieConfig.__instance is None:
            CookieConfig.__instance = CookieConfig(access_token_path, refresh_token_path, cookie_domain, cookie_secure, cookie_same_site)

    @staticmethod
    def reset():
        if ('SUPERTOKENS_ENV' not in environ) or (
                environ['SUPERTOKENS_ENV'] != 'testing'):
            raise_general_exception(
                'calling testing function in non testing env')
        CookieConfig.__instance = None


def save_frontend_info_from_request(request: Request):
    try:
        name = get_header(request, SUPERTOKENS_SDK_NAME_HEADER_GET_KEY)
        version = get_header(request, SUPERTOKENS_SDK_VERSION_HEADER_GET_KEY)
        if name is not None and version is not None:
            DeviceInfo.get_instance().add_to_frontend_sdk({
                'name': name,
                'version': version
            })
    except Exception:
        pass


def set_options_api_headers(response: Response):
    set_header(
        response,
        ACCESS_CONTROL_ALLOW_HEADERS,
        ANTI_CSRF_HEADER_SET_KEY)
    set_header(response, ACCESS_CONTROL_ALLOW_HEADERS,
               SUPERTOKENS_SDK_NAME_HEADER_SET_KEY)
    set_header(response, ACCESS_CONTROL_ALLOW_HEADERS,
               SUPERTOKENS_SDK_VERSION_HEADER_SET_KEY)
    set_header(response, ACCESS_CONTROL_ALLOW_CREDENTIALS, 'true')


def get_cors_allowed_headers():
    return [ANTI_CSRF_HEADER_SET_KEY, SUPERTOKENS_SDK_NAME_HEADER_SET_KEY,
            SUPERTOKENS_SDK_VERSION_HEADER_SET_KEY]


def set_header(response: Response, key, value):
    response.headers.append(key, value)


def get_header(request: Request, key: str):
    return request.headers.get(key)


def get_cookie(request: Request, key: str):
    cookie_val = request.cookies.get(key)
    if cookie_val is None:
        return None
    return unquote(cookie_val)


async def set_cookie(response: Response, key, value, expires, path, domain, secure, http_only, same_site):
    if CookieConfig.get_instance().cookie_domain is not None:
        domain = CookieConfig.get_instance().cookie_domain
    if CookieConfig.get_instance().cookie_secure is not None:
        secure = CookieConfig.get_instance().cookie_secure
    if CookieConfig.get_instance().cookie_same_site is not None:
        same_site = CookieConfig.get_instance().cookie_same_site
    handshake_info = await HandshakeInfo.get_instance()
    if path in {handshake_info.refresh_token_path, handshake_info.access_token_path}:
        if path == handshake_info.access_token_path and CookieConfig.get_instance().access_token_path is not None:
            path = CookieConfig.get_instance().access_token_path
        elif path == handshake_info.refresh_token_path and CookieConfig.get_instance().refresh_token_path is not None:
            path = CookieConfig.get_instance().refresh_token_path
    response.set_cookie(key=key, value=quote(value, encoding='utf-8'), expires=((expires - get_timestamp_ms()) // 1000), path=path,
                        domain=domain, secure=secure, httponly=http_only, samesite=same_site)


def attach_anti_csrf_header(response: Response, value):
    set_header(response, ANTI_CSRF_HEADER_SET_KEY, value)
    set_header(
        response,
        ACCESS_CONTROL_EXPOSE_HEADERS,
        ANTI_CSRF_HEADER_SET_KEY)


def get_anti_csrf_header(request: Request):
    return get_header(request, ANTI_CSRF_HEADER_GET_KEY)


async def attach_access_token_to_cookie(
        response: Response, token, expires_at, domain, path, secure, same_site):
    await set_cookie(response, ACCESS_TOKEN_COOKIE_KEY, token, expires_at, path, domain, secure, True, same_site)


async def attach_refresh_token_to_cookie(
        response: Response, token, expires_at, domain, path, secure, same_site):
    await set_cookie(response, REFRESH_TOKEN_COOKIE_KEY, token, expires_at, path, domain, secure, True, same_site)


async def attach_id_refresh_token_to_cookie_and_header(
        response: Response, token, expires_at, domain, path, secure, same_site):
    set_header(
        response,
        ID_REFRESH_TOKEN_HEADER_SET_KEY,
        token +
        ';' +
        str(expires_at))
    set_header(
        response,
        ACCESS_CONTROL_EXPOSE_HEADERS,
        ID_REFRESH_TOKEN_HEADER_SET_KEY)
    await set_cookie(response, ID_REFRESH_TOKEN_COOKIE_KEY, token, expires_at, path, domain, secure, True, same_site)


def get_access_token_from_cookie(request: Request):
    return get_cookie(request, ACCESS_TOKEN_COOKIE_KEY)


def get_refresh_token_from_cookie(request: Request):
    return get_cookie(request, REFRESH_TOKEN_COOKIE_KEY)


def get_id_refresh_token_from_cookie(request: Request):
    return get_cookie(request, ID_REFRESH_TOKEN_COOKIE_KEY)


async def clear_cookies(response: Response):
    if response is not None:
        handshake_info = await HandshakeInfo.get_instance()
        domain = handshake_info.cookie_domain
        secure = handshake_info.cookie_secure
        access_token_path = handshake_info.access_token_path
        refresh_token_path = handshake_info.refresh_token_path
        id_refresh_token_path = handshake_info.id_refresh_token_path
        same_site = handshake_info.same_site
        await set_cookie(response, ACCESS_TOKEN_COOKIE_KEY, '', 0, access_token_path, domain, secure, True, same_site)
        await set_cookie(response, ID_REFRESH_TOKEN_COOKIE_KEY, '', 0, id_refresh_token_path, domain, secure, True, same_site)
        await set_cookie(response, REFRESH_TOKEN_COOKIE_KEY, '', 0, refresh_token_path, domain, secure, True, same_site)
        set_header(response, ID_REFRESH_TOKEN_HEADER_SET_KEY, "remove")
        set_header(response, ACCESS_CONTROL_EXPOSE_HEADERS, ID_REFRESH_TOKEN_HEADER_SET_KEY)
