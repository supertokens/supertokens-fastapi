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
from jsonschema.exceptions import ValidationError
from jsonschema import validate
from re import fullmatch
from typing import Union, List, Callable, TYPE_CHECKING
if TYPE_CHECKING:
    from fastapi.requests import Request
    from .recipe_module import RecipeModule
from fastapi.responses import JSONResponse
from .constants import RID_KEY_HEADER
from .exceptions import raise_general_exception
from .constants import ERROR_MESSAGE_KEY
from time import time
from base64 import b64encode, b64decode


def validate_the_structure_of_user_input(config, input_schema, config_root, recipe):
    try:
        validate(config, input_schema)
    except ValidationError as e:
        path = '.'.join(e.path)
        if not path == '':
            path = 'for path "' + path + '": '

        error_message = path + e.message

        if 'is a required property' in error_message:
            error_message = 'input config ' + error_message
        if 'Additional properties are not allowed' in error_message:
            error_message += ' Did you mean to set this on the frontend side?'
        error_message = 'Config schema error in ' + config_root + ': ' + error_message

        raise_general_exception(recipe, error_message)


def is_an_ip_address(ip_address: str) -> bool:
    return fullmatch(
        r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|['
        r'01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
        ip_address) is not None


def normalise_http_method(method: str) -> str:
    return method.lower()


def get_rid_from_request(request: Request) -> Union[str, None]:
    return get_header(request, RID_KEY_HEADER)


def get_header(request: Request, key: str) -> Union[str, None]:
    return request.headers.get(key, None)


def find_max_version(versions_1: List[str], versions_2: List[str]) -> Union[str, None]:
    versions = list(set(versions_1) & set(versions_2))
    if len(versions) == 0:
        return None

    max_v = versions[0]
    for i in range(1, len(versions)):
        version = versions[i]
        max_v = compare_version(max_v, version)

    return max_v


def compare_version(v1: str, v2: str) -> str:
    v1_split = v1.split('.')
    v2_split = v2.split('.')
    max_loop = min(len(v1_split), len(v2_split))

    for i in range(max_loop):
        if int(v1_split[i]) > int(v2_split[i]):
            return v1
        elif int(v2_split[i]) > int(v1_split[i]):
            return v2

    if len(v1_split) > len(v2_split):
        return v1

    return v2


def is_4xx_error(status_code: int) -> bool:
    return status_code // 100 == 4


def is_5xx_error(status_code: int) -> bool:
    return status_code // 100 == 5


def send_non_200_response(recipe: Union[RecipeModule, None], message: str, status_code: int) -> JSONResponse:
    if status_code < 300:
        raise_general_exception(recipe, 'Calling sendNon200Response with status code < 300')
    return JSONResponse(
        status_code=status_code,
        content={
            ERROR_MESSAGE_KEY: message
        }
    )


def get_timestamp_ms() -> int:
    return int(time() * 1000)


def utf_base64encode(s: str) -> str:
    return b64encode(s.encode('utf-8')).decode('utf-8')


def utf_base64decode(s: str) -> str:
    return b64decode(s.encode('utf-8')).decode('utf-8')


def get_filtered_list(func: Callable, given_list: List) -> List:
    return list(filter(func, given_list))


def find_first_occurrence_in_list(condition: Callable, given_list: List) -> Union[any, None]:
    for item in given_list:
        if condition(item):
            return item
    return None
