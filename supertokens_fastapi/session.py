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
from supertokens_fastapi import session_helper
from supertokens_fastapi.constants import SESSION_REGENERATE
from supertokens_fastapi.exceptions import raise_unauthorised_exception
from supertokens_fastapi.querier import Querier


class Session:
    def __init__(self, access_token, session_handle,
                 user_id, jwt_payload):
        self.__access_token = access_token
        self.__session_handle = session_handle
        self.__user_id = user_id
        self.__jwt_payload = jwt_payload
        self.new_access_token_info = None
        self.new_refresh_token_info = None
        self.new_id_refresh_token_info = None
        self.new_anti_csrf_token = None
        self.remove_cookies = False

    async def revoke_session(self) -> None:
        if await session_helper.revoke_session(self.__session_handle):
            self.remove_cookies = True

    async def get_session_data(self) -> dict:
        return await session_helper.get_session_data(self.__session_handle)

    async def update_session_data(self, new_session_data) -> None:
        return await session_helper.update_session_data(
            self.__session_handle, new_session_data)

    async def update_jwt_payload(self, new_jwt_payload) -> None:
        result = await Querier.get_instance().send_post_request(SESSION_REGENERATE, {
            'accessToken': self.__access_token,
            'userDataInJWT': new_jwt_payload
        })
        if result['status'] == 'UNAUTHORISED':
            raise_unauthorised_exception(result['message'])
        self.__jwt_payload = result['session']['userDataInJWT']
        if 'accessToken' in result and result['accessToken'] is not None:
            self.__access_token = result['accessToken']['token']
            self.new_access_token_info = result['accessToken']

    def get_user_id(self) -> str:
        return self.__user_id

    def get_jwt_payload(self) -> dict:
        return self.__jwt_payload

    def get_handle(self) -> str:
        return self.__session_handle

    def get_access_token(self) -> str:
        return self.__access_token
