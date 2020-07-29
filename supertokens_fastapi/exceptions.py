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


def raise_general_exception(msg, previous=None):
    if isinstance(msg, SuperTokensError):
        raise msg
    elif isinstance(msg, Exception):
        raise SuperTokensGeneralError(msg) from None
    raise SuperTokensGeneralError(msg) from previous


def raise_token_theft_exception(user_id, session_handle):
    raise SuperTokensTokenTheftError(user_id, session_handle)


def raise_try_refresh_token_exception(msg):
    if isinstance(msg, SuperTokensError):
        raise msg
    raise SuperTokensTryRefreshTokenError(msg) from None


def raise_unauthorised_exception(msg):
    if isinstance(msg, SuperTokensError):
        raise msg
    raise SuperTokensUnauthorisedError(msg) from None


class SuperTokensError(Exception):
    pass


class SuperTokensGeneralError(SuperTokensError):
    pass


class SuperTokensTokenTheftError(SuperTokensError):
    def __init__(self, user_id, session_handle):
        super().__init__('token theft detected')
        self.user_id = user_id
        self.session_handle = session_handle


class SuperTokensUnauthorisedError(SuperTokensError):
    pass


class SuperTokensTryRefreshTokenError(SuperTokensError):
    pass
