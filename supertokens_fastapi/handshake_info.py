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

from supertokens_fastapi.querier import Querier
from supertokens_fastapi.constants import HANDSHAKE
from os import environ
from supertokens_fastapi.exceptions import raise_general_exception
from threading import Lock


class HandshakeInfo:
    __instance = None
    __lock = Lock()

    def __init__(self, info):
        self.access_token_blacklisting_enabled = info['accessTokenBlacklistingEnabled']
        self.access_token_path = info['accessTokenPath']
        self.id_refresh_token_path = info['idRefreshTokenPath']
        if 'cookieDomain' in info:
            self.cookie_domain = info['cookieDomain']
        else:
            self.cookie_domain = None
        self.cookie_secure = info['cookieSecure']
        self.enable_anti_csrf = info['enableAntiCsrf']
        self.jwt_signing_public_key = info['jwtSigningPublicKey']
        self.jwt_signing_public_key_expiry_time = info['jwtSigningPublicKeyExpiryTime']
        self.refresh_token_path = info['refreshTokenPath']
        self.same_site = info['cookieSameSite']
        self.session_expired_status_code = info['sessionExpiredStatusCode']

    @staticmethod
    async def get_instance():
        if HandshakeInfo.__instance is None:
            with HandshakeInfo.__lock:
                if HandshakeInfo.__instance is None:
                    response = await Querier.get_instance().send_post_request(HANDSHAKE, {})
                    HandshakeInfo.__instance = HandshakeInfo(response)
        return HandshakeInfo.__instance

    @staticmethod
    def reset():
        if ('SUPERTOKENS_ENV' not in environ) or (
                environ['SUPERTOKENS_ENV'] != 'testing'):
            raise_general_exception(
                'calling testing function in non testing env')
        HandshakeInfo.__instance = None

    def update_jwt_signing_public_key_info(self, new_key, new_expiry):
        with HandshakeInfo.__lock:
            self.jwt_signing_public_key = new_key
            self.jwt_signing_public_key_expiry_time = new_expiry

    def get_session_expired_status_code(self):
        return self.session_expired_status_code
