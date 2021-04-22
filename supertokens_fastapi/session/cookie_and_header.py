"""
Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.

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
from __future__ import annotations
from typing import Literal
from .constants import (
    ACCESS_TOKEN_COOKIE_KEY,
    REFRESH_TOKEN_COOKIE_KEY,
    ANTI_CSRF_HEADER_SET_KEY,
    ANTI_CSRF_HEADER_GET_KEY,
    FRONT_TOKEN_HEADER_SET_KEY,
    ID_REFRESH_TOKEN_COOKIE_KEY,
    ACCESS_CONTROL_EXPOSE_HEADERS,
    ID_REFRESH_TOKEN_HEADER_SET_KEY
)
from urllib.parse import quote, unquote
from fastapi.requests import Request
from fastapi.responses import Response
from supertokens_fastapi.session.session_recipe import SessionRecipe
from supertokens_fastapi.utils import get_timestamp_ms
from supertokens_fastapi.utils import get_header
from supertokens_fastapi.exceptions import raise_general_exception
from supertokens_fastapi.utils import (
    utf_base64encode
)
from json import (
    dumps
)


def set_front_token_in_headers(recipe: SessionRecipe, response: Response, user_id: str, expires_at: int,
                               jwt_payload=None):
    if jwt_payload is None:
        jwt_payload = {}
    token_info = {
        'uid': user_id,
        'ate': expires_at,
        'up': jwt_payload
    }
    set_header(recipe, response, FRONT_TOKEN_HEADER_SET_KEY, utf_base64encode(dumps(token_info, separators=(',', ':'), sort_keys=True)), False)
    set_header(recipe, response, ACCESS_CONTROL_EXPOSE_HEADERS, FRONT_TOKEN_HEADER_SET_KEY, True)


def get_cors_allowed_headers():
    return [ANTI_CSRF_HEADER_SET_KEY]


def set_header(recipe: SessionRecipe, response: Response, key, value, allow_duplicate: bool):
    try:
        if allow_duplicate:
            response.headers.append(key, value)
        else:
            response.headers[key] = value
    except Exception:
        raise_general_exception(recipe, 'Error while setting header with key: ' + key + ' and value: ' + value)


def get_cookie(request: Request, key: str):
    cookie_val = request.cookies.get(key)
    if cookie_val is None:
        return None
    return unquote(cookie_val)


def set_cookie(recipe: SessionRecipe, response: Response, key, value, expires, path_type: Literal['refresh_token_path', 'access_token_path']):
    domain = recipe.config.cookie_domain
    secure = recipe.config.cookie_secure
    same_site = recipe.config.cookie_same_site
    path = ''
    if path_type == 'refresh_token_path':
        path = recipe.config.refresh_token_path.get_as_string_dangerous()
    elif path_type == 'access_token_path':
        path = '/'
    http_only = True
    response.set_cookie(key=key, value=quote(value, encoding='utf-8'), expires=((expires - get_timestamp_ms()) // 1000),
                        path=path, domain=domain, secure=secure, httponly=http_only, samesite=same_site)


def attach_anti_csrf_header(recipe: SessionRecipe, response: Response, value):
    set_header(recipe, response, ANTI_CSRF_HEADER_SET_KEY, value, False)
    set_header(
        recipe,
        response,
        ACCESS_CONTROL_EXPOSE_HEADERS,
        ANTI_CSRF_HEADER_SET_KEY, True)


def get_anti_csrf_header(request: Request):
    return get_header(request, ANTI_CSRF_HEADER_GET_KEY)


def attach_access_token_to_cookie(
        recipe: SessionRecipe, response: Response, token, expires_at):
    set_cookie(recipe, response, ACCESS_TOKEN_COOKIE_KEY, token, expires_at, 'access_token_path')


def attach_refresh_token_to_cookie(
        recipe: SessionRecipe, response: Response, token, expires_at):
    set_cookie(recipe, response, REFRESH_TOKEN_COOKIE_KEY, token, expires_at, 'refresh_token_path')


def attach_id_refresh_token_to_cookie_and_header(
        recipe: SessionRecipe, response: Response, token, expires_at):
    set_header(
        recipe,
        response,
        ID_REFRESH_TOKEN_HEADER_SET_KEY,
        token +
        ';' +
        str(expires_at),
        False
    )
    set_header(
        recipe,
        response,
        ACCESS_CONTROL_EXPOSE_HEADERS,
        ID_REFRESH_TOKEN_HEADER_SET_KEY,
        True
    )
    set_cookie(recipe, response, ID_REFRESH_TOKEN_COOKIE_KEY, token, expires_at, 'access_token_path')


def get_access_token_from_cookie(request: Request):
    return get_cookie(request, ACCESS_TOKEN_COOKIE_KEY)


def get_refresh_token_from_cookie(request: Request):
    return get_cookie(request, REFRESH_TOKEN_COOKIE_KEY)


def get_id_refresh_token_from_cookie(request: Request):
    return get_cookie(request, ID_REFRESH_TOKEN_COOKIE_KEY)


def clear_cookies(recipe: SessionRecipe, response: Response):
    if response is not None:
        set_cookie(recipe, response, ACCESS_TOKEN_COOKIE_KEY, '', 0, 'access_token_path')
        set_cookie(recipe, response, ID_REFRESH_TOKEN_COOKIE_KEY, '', 0, 'refresh_token_path')
        set_cookie(recipe, response, REFRESH_TOKEN_COOKIE_KEY, '', 0, 'access_token_path')
        set_header(recipe, response, ID_REFRESH_TOKEN_HEADER_SET_KEY, "remove", False)
        set_header(recipe, response, ACCESS_CONTROL_EXPOSE_HEADERS, ID_REFRESH_TOKEN_HEADER_SET_KEY, True)
