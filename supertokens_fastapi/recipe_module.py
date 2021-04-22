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
from .querier import Querier
import abc
from .supertokens import AppInfo
from typing import Union, Literal, List
from .normalised_url_path import NormalisedURLPath
from fastapi.requests import Request
from .exceptions import SuperTokensError


class RecipeModule(abc.ABC):
    def __init__(self, recipe_id: str, app_info: AppInfo, is_in_serverless_env: bool,
                 rid_to_core: Union[str, None] = None):
        self.recipe_id = recipe_id
        self.app_info = app_info
        self.is_in_serverless_env = is_in_serverless_env
        self.rid_to_core = rid_to_core
        self.querier = None

    def get_recipe_id(self):
        return self.recipe_id

    def get_app_info(self):
        return self.app_info

    def check_if_in_serverless_env(self):
        return self.is_in_serverless_env

    def get_querier(self):
        if self.querier is None:
            self.querier = Querier.get_instance(self.is_in_serverless_env, self, self.rid_to_core)
        return self.querier

    def return_api_id_if_can_handle_request(self, path: NormalisedURLPath, method: str) -> Union[str, None]:
        pass

    @abc.abstractmethod
    def is_error_from_this_or_child_recipe_based_on_instance(self, err):
        pass

    @abc.abstractmethod
    def get_apis_handled(self) -> List[APIHandled]:
        pass

    @abc.abstractmethod
    async def handle_api_request(self, request_id: str, request: Request, path: NormalisedURLPath, method: str):
        pass

    @abc.abstractmethod
    async def handle_error(self, request: Request, err: SuperTokensError):
        pass

    @abc.abstractmethod
    def get_all_cors_headers(self):
        pass


class APIHandled:
    def __init__(self, path_without_api_base_path: NormalisedURLPath, method: Literal['post', 'get', 'delete', 'put', 'options', 'trace'], request_id: str, disabled: bool):
        self.path_without_api_base_path = path_without_api_base_path
        self.method = method
        self.request_id = request_id
        self.disabled = disabled
