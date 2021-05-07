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
    API_VERSION,
    API_KEY_HEADER,
    RID_KEY_HEADER,
    SUPPORTED_CDI_VERSIONS,
    API_VERSION_HEADER
)
from json import JSONDecodeError
from os import environ
from httpx import AsyncClient, NetworkError, ConnectTimeout
from .normalised_url_path import NormalisedURLPath
from typing import Union, TYPE_CHECKING
if TYPE_CHECKING:
    from .recipe_module import RecipeModule
from .exceptions import raise_general_exception
from .utils import (
    is_4xx_error,
    is_5xx_error,
    find_max_version
)
from .process_state import AllowedProcessStates, ProcessState


class Querier:
    __init_called = False
    __hosts = None
    __api_key = None
    __api_version = None
    __last_tried_index: int = 0
    __hosts_alive_for_testing = set()

    def __init__(self, hosts: list, is_in_serverless_env: bool, recipe: Union[RecipeModule, None], rid_to_core=None):
        self.__hosts = hosts
        self.__recipe = recipe
        self.__rid_to_core = None
        if rid_to_core is not None:
            self.__rid_to_core = rid_to_core
        elif self.__recipe is not None:
            self.__rid_to_core = self.__recipe.get_recipe_id()
        self.__is_in_serverless_env = is_in_serverless_env

    @staticmethod
    def reset():
        if ('SUPERTOKENS_ENV' not in environ) or (
                environ['SUPERTOKENS_ENV'] != 'testing'):
            raise_general_exception(None, 'calling testing function in non testing env')
        Querier.__init_called = False

    @staticmethod
    def get_hosts_alive_for_testing():
        if ('SUPERTOKENS_ENV' not in environ) or (
                environ['SUPERTOKENS_ENV'] != 'testing'):
            raise_general_exception(None, 'calling testing function in non testing env')
        return Querier.__hosts_alive_for_testing

    async def get_api_version(self):
        if Querier.__api_version is not None:
            return Querier.__api_version

        # TODO: server-less
        ProcessState.get_instance().add_state(AllowedProcessStates.CALLING_SERVICE_IN_GET_API_VERSION)

        async def f(url):
            headers = {}
            if Querier.__api_key is not None:
                headers = {
                    API_KEY_HEADER: Querier.__api_key
                }
            return await AsyncClient().get(url, headers=headers)

        response = await self.__send_request_helper(
            NormalisedURLPath(self.__recipe, API_VERSION), 'GET', f, len(self.__hosts))
        cdi_supported_by_server = response['versions']
        api_version = find_max_version(
            cdi_supported_by_server,
            SUPPORTED_CDI_VERSIONS)

        if api_version is None:
            raise_general_exception(None, 'The running SuperTokens core version is not compatible with this FastAPI '
                                          'SDK. Please visit https://supertokens.io/docs/community/compatibility to '
                                          'find the right versions')

        Querier.__api_version = api_version
        # TODO: server-less
        return Querier.__api_version

    @staticmethod
    def get_instance(is_in_serverless_env: bool, recipe, rid_to_core=None):
        if (not Querier.__init_called) or (Querier.__hosts is None):
            # TODO
            raise Exception("Please call the supertokens.init function before using SuperTokens")
        return Querier(Querier.__hosts, is_in_serverless_env, recipe, rid_to_core)

    @staticmethod
    def init(hosts, api_key=None):
        if not Querier.__init_called:
            Querier.__init_called = True
            Querier.__hosts = hosts
            Querier.__api_key = api_key
            Querier.__api_version = None
            Querier.__last_tried_index = 0
            Querier.__hosts_alive_for_testing = set()

    async def __get_headers_with_api_version(self, path):
        headers = {
            API_VERSION_HEADER: await self.get_api_version()
        }
        if Querier.__api_key is not None:
            headers = {
                **headers,
                API_KEY_HEADER: Querier.__api_key
            }
        if path.is_a_recipe_path() and self.__rid_to_core is not None:
            headers = {
                **headers,
                RID_KEY_HEADER: self.__rid_to_core
            }
        return headers

    async def send_get_request(self, path: NormalisedURLPath, params=None):
        if params is None:
            params = {}

        async def f(url):
            return await AsyncClient().get(url, params=params, headers=await self.__get_headers_with_api_version(path))

        return await self.__send_request_helper(path, 'GET', f, len(self.__hosts))

    async def send_post_request(self, path: NormalisedURLPath, data=None, test=False):
        if data is None:
            data = {}

        if ('SUPERTOKENS_ENV' in environ) and (
                environ['SUPERTOKENS_ENV'] == 'testing') and test:
            return data

        async def f(url):
            return await AsyncClient().post(url, json=data, headers=await self.__get_headers_with_api_version(path))

        return await self.__send_request_helper(path, 'POST', f, len(self.__hosts))

    async def send_delete_request(self, path: NormalisedURLPath):

        async def f(url):
            return await AsyncClient().delete(url, headers=await self.__get_headers_with_api_version(path))

        return await self.__send_request_helper(path, 'DELETE', f, len(self.__hosts))

    async def send_put_request(self, path: NormalisedURLPath, data=None):
        if data is None:
            data = {}

        async def f(url):
            return await AsyncClient().put(url, json=data, headers=await self.__get_headers_with_api_version(path))

        return await self.__send_request_helper(path, 'PUT', f, len(self.__hosts))

    async def __send_request_helper(self, path: NormalisedURLPath, method, http_function, no_of_tries):
        if no_of_tries == 0:
            raise_general_exception(self.__recipe, 'No SuperTokens core available to query')

        try:
            current_host = self.__hosts[Querier.__last_tried_index].get_as_string_dangerous()
            Querier.__last_tried_index += 1
            Querier.__last_tried_index %= len(self.__hosts)
            url = current_host + path.get_as_string_dangerous()

            ProcessState.get_instance().add_state(AllowedProcessStates.CALLING_SERVICE_IN_REQUEST_HELPER)
            response = await http_function(url)
            if ('SUPERTOKENS_ENV' in environ) and (
                    environ['SUPERTOKENS_ENV'] == 'testing'):
                Querier.__hosts_alive_for_testing.add(current_host)

            if is_4xx_error(response.status_code) or is_5xx_error(response.status_code):
                raise_general_exception(None, 'SuperTokens core threw an error for a ' + method + ' request to path: ' +
                                        path.get_as_string_dangerous() + ' with status code: ' + str(response.status_code) + ' and message: ' +
                                        response.text)

            try:
                return response.json()
            except JSONDecodeError:
                return response.text

        except (ConnectionError, NetworkError, ConnectTimeout):
            return await self.__send_request_helper(
                path, method, http_function, no_of_tries - 1)

        # TODO
        except Exception as e:
            raise_general_exception(None, e)
