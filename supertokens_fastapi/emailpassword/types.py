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
from typing import Callable, Union, Awaitable, List

type_string = {
    'type': 'string'
}

type_boolean = {
    'type': 'boolean'
}

type_number = {
    'type': 'number'
}

type_any = {}

SESSION_FEATURE_INPUT_SCHEMA = {
    'type': 'object',
    'properties': {
        'set_jwt_payload': type_any,
        'set_session_data': type_any
    },
    'additionalProperties': False
}

SIGN_UP_FEATURE_INPUT_SCHEMA = {
    'type': 'object',
    'properties': {
        'disable_default_implementation': type_boolean,
        'form_fields': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'id': type_string,
                    'validate': type_any,
                    'optional': type_boolean
                },
                'required': ['id'],
                'additionalProperties': False
            }
        },
        'handle_post_sign_up': type_any
    },
    'additionalProperties': False
}

SIGN_IN_FEATURE_INPUT_SCHEMA = {
    'type': 'object',
    'properties': {
        'disable_default_implementation': type_boolean,
        'handle_post_sign_in': type_any
    },
    'additionalProperties': False
}

SIGN_OUT_FEATURE_INPUT_SCHEMA = {
    'type': 'object',
    'properties': {
        'disable_default_implementation': type_boolean
    },
    'additionalProperties': False
}

RESET_PASSWORD_USING_TOKEN_FEATURE_INPUT_SCHEMA = {
    'type': 'object',
    'properties': {
        'disable_default_implementation': type_boolean,
        'get_reset_password_url': type_any,
        'create_and_send_custom_email': type_any
    },
    'additionalProperties': False
}

EMAIL_VERIFICATION_FEATURE_INPUT_SCHEMA = {
    'type': 'object',
    'properties': {
        'disable_default_implementation': type_boolean,
        'get_email_verification_url': type_any,
        'create_and_send_custom_email': type_any,
        'handle_post_email_verification': type_any
    },
    'additionalProperties': False
}

INPUT_SCHEMA = {
    'type': 'object',
    'properties': {
        'session_feature': SESSION_FEATURE_INPUT_SCHEMA,
        'sign_up_feature': SIGN_UP_FEATURE_INPUT_SCHEMA,
        'sign_in_feature': SIGN_IN_FEATURE_INPUT_SCHEMA,
        'sign_out_feature': SIGN_OUT_FEATURE_INPUT_SCHEMA,
        'reset_token_using_password_feature': RESET_PASSWORD_USING_TOKEN_FEATURE_INPUT_SCHEMA,
        'email_verification_feature': EMAIL_VERIFICATION_FEATURE_INPUT_SCHEMA
    },
    'additionalProperties': False
}


class User:
    def __init__(self, user_id: str, email: str, time_joined: int):
        self.user_id = user_id
        self.email = email
        self.time_joined = time_joined


class UsersResponse:
    def __init__(self, users: List[User], next_pagination_token: Union[str, None]):
        self.users = users
        self.next_pagination_token = next_pagination_token


class ErrorFormField:
    def __init__(self, id: str, error: str):
        self.id = id
        self.error = error


class FormField:
    def __init__(self, id: str, value: any):
        self.id = id
        self.value = value


class NormalisedFormField:
    def __init__(self, id: str, validate: Callable[[str], Awaitable[Union[str, None]]], optional: bool):
        self.id = id
        self.validate = validate
        self.optional = optional
