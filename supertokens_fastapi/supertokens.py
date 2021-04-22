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
from .constants import (
    TELEMETRY,
    RID_KEY_HEADER,
    FDI_KEY_HEADER,
    TELEMETRY_SUPERTOKENS_API_URL,
    TELEMETRY_SUPERTOKENS_API_VERSION
)
from .session.cookie_and_header import clear_cookies, attach_access_token_to_cookie, \
    attach_refresh_token_to_cookie, attach_id_refresh_token_to_cookie_and_header, attach_anti_csrf_header
from .utils import (
    validate_the_structure_of_user_input,
    normalise_http_method,
    get_rid_from_request,
    send_non_200_response
)
from .types import INPUT_SCHEMA
from .normalised_url_domain import NormalisedURLDomain
from .normalised_url_path import NormalisedURLPath
from .querier import Querier
from .recipe_module import RecipeModule
from typing import Union, List
from os import environ
from httpx import AsyncClient
from .exceptions import raise_general_exception
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.requests import Request
from fastapi.responses import Response
from .session.session_class import Session
from .exceptions import (
    SuperTokensError,
    GeneralError,
    BadInputError
)
from .session.session_recipe import SessionRecipe


class AppInfo:
    def __init__(self, recipe: Union[RecipeModule, None], app_info, api_web_proxy_path: NormalisedURLPath):
        self.app_name: str = app_info['app_name']
        self.api_domain: NormalisedURLDomain = NormalisedURLDomain(recipe, app_info['api_domain'])
        self.website_domain: NormalisedURLDomain = NormalisedURLDomain(recipe, app_info['website_domain'])
        self.api_base_path: NormalisedURLPath = api_web_proxy_path.append(recipe, NormalisedURLPath(recipe, '/auth') if 'api_base_path' not in app_info else NormalisedURLPath(recipe, app_info['api_base_path']))
        self.website_base_path: NormalisedURLPath = NormalisedURLPath(recipe, '/auth') if 'website_base_path' not in app_info else NormalisedURLPath(recipe, app_info['website_base_path'])


def manage_cookies_post_response(session: Session, response: Response):
    recipe = SessionRecipe.get_instance()
    if session.remove_cookies:
        clear_cookies(recipe, response)
    else:
        access_token = session.new_access_token_info
        if access_token is not None:
            attach_access_token_to_cookie(
                recipe,
                response,
                access_token['token'],
                access_token['expiry']
            )
        refresh_token = session.new_refresh_token_info
        if refresh_token is not None:
            attach_refresh_token_to_cookie(
                recipe,
                response,
                refresh_token['token'],
                refresh_token['expiry']
            )
        id_refresh_token = session.new_id_refresh_token_info
        if id_refresh_token is not None:
            attach_id_refresh_token_to_cookie_and_header(
                recipe,
                response,
                id_refresh_token['token'],
                id_refresh_token['expiry']
            )
        anti_csrf_token = session.new_anti_csrf_token
        if anti_csrf_token is not None:
            attach_anti_csrf_header(recipe, response, anti_csrf_token)


class Supertokens:
    __instance = None

    def __init__(self, config, app: FastAPI):
        validate_the_structure_of_user_input(config, INPUT_SCHEMA, 'init_function', None)
        self.api_web_proxy_path = NormalisedURLPath(None, config['api_web_proxy_path']) if 'api_web_proxy_path' in config else NormalisedURLPath(None, '')
        self.app_info: AppInfo = AppInfo(None, config['app_info'], self.api_web_proxy_path)

        hosts = list(map(lambda h: NormalisedURLDomain(None, h.strip()), filter(lambda x: x != '', config['supertokens']['connectionURI'].split(';'))))
        api_key = None
        if 'api_key' in config['supertokens']:
            api_key = config['supertokens']['api_key']
        Querier.init(hosts, api_key)

        if 'recipe_list' not in config or len(config['recipe_list'] == 0):
            raise_general_exception(None, 'Please provide at least one recipe to the supertokens.init function call')

        # TODO server-less

        self.is_in_serverless_env = False if 'is_in_serverless_env' not in config else config['is_in_serverless_env']
        self.recipe_modules: List[RecipeModule] = list(map(lambda func: func(self.app_info, self.is_in_serverless_env), config['recipe_list']))

        for recipe in self.recipe_modules:
            apis_handled = recipe.get_apis_handled()
            stringified_apis_handled: List[str] = list(filter(lambda x: x != "", map(lambda api: '' if api.disabled else api.method + ';' + api.path_without_api_base_path.get_as_string_dangerous(), apis_handled)))
            if len(stringified_apis_handled) != len(set(stringified_apis_handled)):
                raise_general_exception(recipe, 'Duplicate APIs exposed from recipe. Please combine them into one API')

        telemetry = ('SUPERTOKENS_ENV' not in environ) or (environ['SUPERTOKENS_ENV'] != 'testing')
        if 'telemetry' in config:
            telemetry = config['telemetry']

        if telemetry:
            self.send_telemetry()

        app.add_middleware(self.__Middleware)
        self.__set_error_handler(app)

    async def send_telemetry(self):
        try:
            querier = Querier.get_instance(self.is_in_serverless_env, None)
            response = await querier.send_get_request(NormalisedURLPath(None, TELEMETRY), {})
            telemetry_id = None
            if 'exists' in response and response['exists'] and 'telemetry_id' in response:
                telemetry_id = response['telemetry_id']
            data = {
                'appName': self.app_info.app_name,
                'websiteDomain': self.app_info.website_domain.get_as_string_dangerous()
            }
            if telemetry_id is not None:
                data = {
                    **data,
                    'telemetryId': telemetry_id
                }
            await AsyncClient.post(url=TELEMETRY_SUPERTOKENS_API_URL, json=data, headers={'api-version': TELEMETRY_SUPERTOKENS_API_VERSION})
        except Exception:
            pass

    @staticmethod
    def init(config, app: FastAPI = None):
        if Supertokens.__instance is None:
            Supertokens.__instance = Supertokens(config, app)

    @staticmethod
    def reset():
        if ('SUPERTOKENS_ENV' not in environ) or (
                environ['SUPERTOKENS_ENV'] != 'testing'):
            raise_general_exception(None, 'calling testing function in non testing env')
        Querier.reset()
        Supertokens.__instance = None

    @staticmethod
    def get_instance() -> Supertokens:
        if Supertokens.__instance is not None:
            return Supertokens.__instance
        raise_general_exception(None, 'Initialisation not done. Did you forget to call the SuperTokens.init function?')

    def __set_error_handler(self, app: FastAPI):
        @app.exception_handler(SuperTokensError)
        async def handle_supertokens_error(request: Request, err: SuperTokensError):
            if isinstance(err, GeneralError):
                raise Exception(err)

            if isinstance(err, BadInputError):
                return send_non_200_response(err.recipe, str(err), 400)

            for recipe in self.recipe_modules:
                if recipe.is_error_from_this_or_child_recipe_based_on_instance(err):
                    return recipe.handle_error(request, err)

            raise err

    def get_all_cors_headers(self) -> List[str]:
        headers_set = set()
        headers_set.add(RID_KEY_HEADER)
        headers_set.add(FDI_KEY_HEADER)
        for recipe in self.recipe_modules:
            headers = recipe.get_all_cors_headers()
            for header in headers:
                headers_set.add(header)

        return list(headers_set)

    class __Middleware(BaseHTTPMiddleware):
        def __init__(self, app: FastAPI):
            super().__init__(app)

        async def dispatch(self, request: Request, call_next):
            path = Supertokens.get_instance().api_web_proxy_path.append(None, NormalisedURLPath(None, request.url.path))
            method = normalise_http_method(request.method)

            if not path.startswith(Supertokens.get_instance().app_info.api_base_path):
                response = await call_next(request)
            else:
                request_rid = get_rid_from_request(request)
                request_id = None
                matched_recipe = None
                if request_rid is not None:
                    for recipe in Supertokens.get_instance().recipe_modules:
                        if recipe.get_recipe_id() == request_rid:
                            matched_recipe = recipe
                            break
                    if matched_recipe is not None:
                        request_id = matched_recipe.return_api_id_if_can_handle_request(path, method)
                else:
                    for recipe in Supertokens.get_instance().recipe_modules:
                        request_id = recipe.return_api_id_if_can_handle_request(path, method)
                        if request_id is not None:
                            matched_recipe = recipe
                            break
                if request_id is not None and matched_recipe is not None:
                    response = await matched_recipe.handle_api_request(request_id, request, path, method)
                else:
                    response = await call_next(request)
            if hasattr(request.state, "supertokens") and isinstance(request.state.supertokens, Session):
                manage_cookies_post_response(request.state.supertokens, response)
            return response
