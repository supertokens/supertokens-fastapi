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
from .cookie_and_header import clear_cookies
from .session_recipe import SessionRecipe
from supertokens_fastapi.supertokens import AppInfo
from supertokens_fastapi.utils import validate_the_structure_of_user_input, is_an_ip_address, send_non_200_response
from .types import INPUT_SCHEMA
from urllib.parse import urlparse
from supertokens_fastapi.exceptions import raise_general_exception
from tldextract import extract
from supertokens_fastapi.normalised_url_path import NormalisedURLPath
from .constants import SESSION_REFRESH
from fastapi.requests import Request


def normalise_session_scope(recipe: SessionRecipe, session_scope: str) -> str:
    def helper(scope: str) -> str:
        scope = scope.strip()

        if scope.startswith('.'):
            scope = scope[1:]

        if (not scope.startswith('https://')) and (not scope.startswith('http://')):
            scope = 'http://' + scope

        try:
            url_obj = urlparse(scope)
            scope = url_obj.hostname

            if scope.startswith('.'):
                scope = scope[1:]

            return scope
        except Exception:
            raise_general_exception(recipe, 'Please provide a valid sessionScope')

    no_dot_normalised = helper(session_scope)
    if no_dot_normalised == 'localhost' or is_an_ip_address(no_dot_normalised):
        return no_dot_normalised

    if no_dot_normalised.startswith('.'):
        return no_dot_normalised[1:]

    return no_dot_normalised


def normalise_same_site(recipe: SessionRecipe, same_site: str) -> str:
    same_site = same_site.strip()
    same_site = same_site.lower()
    allowed_values = {'strict', 'lax', 'none'}
    if same_site not in allowed_values:
        raise_general_exception(recipe, 'cookie same site must be one of "strict", "lax", or "none"')
    return same_site


def get_top_level_domain_for_same_site_resolution(url: str, recipe: SessionRecipe) -> str:
    url_obj = urlparse(url)
    hostname = url_obj.hostname

    if hostname.startswith('localhost') or is_an_ip_address(hostname):
        return 'localhost'
    parsed_url = extract(hostname)
    if parsed_url == '':
        raise_general_exception(recipe, 'Please make sure that the apiDomain and websiteDomain have correct values')

    return parsed_url.domain


class SessionRefreshFeature:
    def __init__(self, disable_default_implementation: bool):
        self.disable_default_implementation = disable_default_implementation


class SignOutFeature:
    def __init__(self, disable_default_implementation: bool):
        self.disable_default_implementation = disable_default_implementation


class ErrorHandlers:
    def __init__(self, recipe: SessionRecipe, on_token_theft_detected, on_try_refresh_token, on_unauthorised):
        self.__recipe = recipe
        self.__on_token_theft_detected = on_token_theft_detected
        self.__on_try_refresh_token = on_try_refresh_token
        self.__on_unauthorised = on_unauthorised

    async def on_token_theft_detected(self, request: Request, session_handle: str, user_id: str):
        try:
            response = await self.__on_token_theft_detected(request, session_handle, user_id)
        except TypeError:
            response = self.__on_token_theft_detected(request, session_handle, user_id)
        clear_cookies(self.__recipe, response)
        return response

    async def on_try_refresh_token(self, request: Request, message: str):
        try:
            response = await self.__on_try_refresh_token(request, message)
        except TypeError:
            response = self.__on_try_refresh_token(request, message)
        return response

    async def on_unauthorised(self, request: Request, message: str):
        try:
            response = await self.__on_unauthorised(request, message)
        except TypeError:
            response = self.__on_unauthorised(request, message)
        clear_cookies(self.__recipe, response)
        return response


async def default_unauthorised_callback(_: Request, __: str):
    return send_non_200_response(SessionRecipe.get_instance(), 'unauthorised', SessionRecipe.get_instance().config.session_expired_status_code)


async def default_try_refresh_token_callback(_: Request, __: str):
    return send_non_200_response(SessionRecipe.get_instance(), 'try refresh token', SessionRecipe.get_instance().config.session_expired_status_code)


async def default_token_theft_detected_callback(_: Request, session_handle: str, __: str):
    await SessionRecipe.get_instance().revoke_session(session_handle)
    return send_non_200_response(SessionRecipe.get_instance(), 'token theft detected', SessionRecipe.get_instance().config.session_expired_status_code)


class SessionConfig:
    def __init__(self,
                 refresh_token_path: NormalisedURLPath,
                 cookie_domain: str,
                 cookie_same_site: str,
                 cookie_secure: str,
                 session_expired_status_code: int,
                 session_refresh_feature: SessionRefreshFeature,
                 error_handlers: ErrorHandlers,
                 enable_anti_csrf: bool,
                 sign_out_feature: SignOutFeature
                 ):
        self.refresh_token_path = refresh_token_path
        self.cookie_domain = cookie_domain
        self.cookie_same_site = cookie_same_site
        self.cookie_secure = cookie_secure
        self.session_expired_status_code = session_expired_status_code
        self.session_refresh_feature = session_refresh_feature
        self.error_handlers = error_handlers
        self.enable_anti_csrf = enable_anti_csrf
        self.sign_out_feature = sign_out_feature


def validate_and_normalise_user_input(recipe: SessionRecipe, app_info: AppInfo, config=None):
    if config is None:
        config = {}

    validate_the_structure_of_user_input(config, INPUT_SCHEMA, 'session recipe', recipe)
    cookie_domain = normalise_session_scope(recipe, config['cookie_domain']) if 'cookie_domain' in config else None
    top_level_api_domain = get_top_level_domain_for_same_site_resolution(app_info.api_domain.get_as_string_dangerous(),
                                                                         recipe)
    top_level_website_domain = get_top_level_domain_for_same_site_resolution(
        app_info.website_domain.get_as_string_dangerous(), recipe)
    cookie_same_site = 'none' if top_level_api_domain != top_level_website_domain else 'lax'
    if 'cookie_same_site' in config:
        cookie_same_site = normalise_same_site(recipe, config['cookie_same_site'])

    cookie_secure = config[
        'cookie_secure'] if 'cookie_secure' in config else app_info.api_domain.get_as_string_dangerous().startswith(
        'https')
    session_expired_status_code = config[
        'session_expired_status_code'] if 'session_expired_status_code' in config else 401
    session_refresh_feature_disable_default_implementation = False
    if 'session_refresh_feature' in config and 'disable_default_implementation' in config['session_refresh_feature']:
        session_refresh_feature_disable_default_implementation = config['session_refresh_feature'][
            'disable_default_implementation']
    session_refresh_feature = SessionRefreshFeature(session_refresh_feature_disable_default_implementation)
    sign_out_feature_disable_default_implementation = False
    if 'sign_out_feature' in config and 'disable_default_implementation' in config['sign_out_feature']:
        sign_out_feature_disable_default_implementation = config['sign_out_feature'][
            'disable_default_implementation']
    sign_out_feature = SignOutFeature(sign_out_feature_disable_default_implementation)
    enable_anti_csrf = config['enable_anti_csrf'] if 'enable_anti_csrf' in config else cookie_same_site == 'none'

    on_token_theft_detected = default_token_theft_detected_callback
    on_try_refresh_token = default_try_refresh_token_callback
    on_unauthorised = default_unauthorised_callback
    if 'error_handlers' in config and 'on_token_theft_detected' in config['error_handlers']:
        on_token_theft_detected = config['error_handlers']['on_token_theft_detected']
    if 'error_handlers' in config and 'on_unauthorised' in config['error_handlers']:
        on_unauthorised = config['error_handlers']['on_unauthorised']
    error_handlers = ErrorHandlers(
        on_token_theft_detected,
        on_try_refresh_token,
        on_unauthorised
    )
    if cookie_same_site == 'none' and not enable_anti_csrf:
        raise_general_exception(recipe, 'Security error: enableAntiCsrf can\'t be set to false if cookieSameSite '
                                        'value is "none".')

    if (cookie_same_site == 'none') and \
            not cookie_secure and \
            not (top_level_api_domain == 'localhost' or is_an_ip_address(top_level_api_domain)) and \
            not (top_level_website_domain == 'localhost' or is_an_ip_address(top_level_website_domain)):
        raise_general_exception('Since your API and website domain are different, for sessions to work, please use '
                                'https on your apiDomain and don\'t set cookieSecure to false.')

    return SessionConfig(
        app_info.api_base_path.append(recipe, NormalisedURLPath(recipe, SESSION_REFRESH)),
        cookie_domain,
        cookie_same_site,
        cookie_secure,
        session_expired_status_code,
        session_refresh_feature,
        error_handlers,
        enable_anti_csrf,
        sign_out_feature
    )
