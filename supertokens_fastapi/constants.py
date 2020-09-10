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

HOSTS_CONFIG = 'SUPERTOKENS_HOSTS'
ACCESS_TOKEN_PATH_CONFIG = 'SUPERTOKENS_ACCESS_TOKEN_PATH'
REFRESH_TOKEN_PATH_CONFIG = 'SUPERTOKENS_REFRESH_TOKEN_PATH'
COOKIE_DOMAIN_CONFIG = 'SUPERTOKENS_COOKIE_DOMAIN'
COOKIE_SECURE_CONFIG = 'SUPERTOKENS_COOKIE_SECURE'
COOKIE_SAME_SITE_CONFIG = 'SUPERTOKENS_COOKIE_SAME_SITE'
DEFAULT_HOSTS = 'http://localhost:3567'
API_VERSION_HEADER = 'cdi-version'
SUPPORTED_CDI_VERSIONS = ['2.0', '2.1', '2.2', '2.3']
VERSION = '1.1.0'
API_VERSION = '/apiversion'
SESSION = '/session'
SESSION_REMOVE = '/session/remove'
SESSION_VERIFY = '/session/verify'
SESSION_REFRESH = '/session/refresh'
SESSION_USER = '/session/user'
SESSION_DATA = '/session/data'
HELLO = '/hello'
CONFIG = '/config'
HANDSHAKE = '/handshake'
JWT_DATA = '/jwt/data'
SESSION_REGENERATE = '/session/regenerate'
DRIVER_NOT_COMPATIBLE_MESSAGE = 'Current driver version is not compatible with the core version on your host/s'
ACCESS_TOKEN_SIGNING_KEY_NAME_IN_DB = 'access_token_signing_key'
REFRESH_TOKEN_KEY_NAME_IN_DB = 'refresh_token_key'
ACCESS_TOKEN_COOKIE_KEY = 'sAccessToken'
REFRESH_TOKEN_COOKIE_KEY = 'sRefreshToken'
ID_REFRESH_TOKEN_COOKIE_KEY = 'sIdRefreshToken'
ANTI_CSRF_HEADER_SET_KEY = 'anti-csrf'
ANTI_CSRF_HEADER_GET_KEY = 'anti-csrf'
ID_REFRESH_TOKEN_HEADER_SET_KEY = 'id-refresh-token'
ID_REFRESH_TOKEN_HEADER_GET_KEY = 'id-refresh-token'
SUPERTOKENS_SDK_NAME_HEADER_SET_KEY = 'supertokens-sdk-name'
SUPERTOKENS_SDK_NAME_HEADER_GET_KEY = 'supertokens-sdk-name'
SUPERTOKENS_SDK_VERSION_HEADER_SET_KEY = 'supertokens-sdk-version'
SUPERTOKENS_SDK_VERSION_HEADER_GET_KEY = 'supertokens-sdk-version'
ACCESS_CONTROL_EXPOSE_HEADERS = 'Access-Control-Expose-Headers'
ACCESS_CONTROL_ALLOW_HEADERS = 'Access-Control-Allow-Headers'
ACCESS_CONTROL_ALLOW_CREDENTIALS = 'Access-Control-Allow-Credentials'
ERROR_MESSAGE_KEY = 'error'
API_KEY_HEADER = 'api-key'
