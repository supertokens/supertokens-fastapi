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
from supertokens_fastapi.constants import (
    SESSION,
    JWT_DATA,
    SESSION_DATA,
    SESSION_USER,
    SESSION_VERIFY,
    SESSION_REMOVE,
    SESSION_REFRESH
)
from supertokens_fastapi.handshake_info import HandshakeInfo
from supertokens_fastapi.exceptions import (
    raise_general_exception,
    raise_token_theft_exception,
    raise_unauthorised_exception,
    SuperTokensTryRefreshTokenError,
    raise_try_refresh_token_exception
)
from supertokens_fastapi.utils import get_timestamp_ms
from supertokens_fastapi.access_token import get_info_from_access_token
from supertokens_fastapi.process_state import ProcessState
from os import environ
from typing import List, Union


def init(hosts: Union[str, None], api_key: Union[str, None]):
    Querier.init_instance(hosts, api_key)


def reset():
    if ('SUPERTOKENS_ENV' not in environ) or (
            environ['SUPERTOKENS_ENV'] != 'testing'):
        raise_general_exception('calling testing function in non testing env')
    ProcessState.reset()


async def create_new_session(user_id: str, jwt_payload: Union[dict, None] = None, session_data: Union[dict, None] = None):
    if session_data is None:
        session_data = {}
    if jwt_payload is None:
        jwt_payload = {}

    response = await Querier.get_instance().send_post_request(SESSION, {
        'userId': user_id,
        'userDataInJWT': jwt_payload,
        'userDataInDatabase': session_data
    })
    (await HandshakeInfo.get_instance()).update_jwt_signing_public_key_info(response['jwtSigningPublicKey'],
                                                                            response['jwtSigningPublicKeyExpiryTime'])
    response.pop('status', None)
    response.pop('jwtSigningPublicKey', None)
    response.pop('jwtSigningPublicKeyExpiryTime', None)

    return response


async def get_session(access_token: str, anti_csrf_token: Union[str, None], do_anti_csrf_check: bool):
    handshake_info = await HandshakeInfo.get_instance()

    try:
        if handshake_info.jwt_signing_public_key_expiry_time > get_timestamp_ms():
            access_token_info = get_info_from_access_token(access_token, handshake_info.jwt_signing_public_key,
                                                           handshake_info.enable_anti_csrf and do_anti_csrf_check)

            if handshake_info.enable_anti_csrf and do_anti_csrf_check and \
                    (anti_csrf_token is None or anti_csrf_token != access_token_info['antiCsrfToken']):
                if anti_csrf_token is None:
                    raise_try_refresh_token_exception('anti_csrf_token is undefined')
                raise_try_refresh_token_exception('anti-csrf check failed')

            if not handshake_info.access_token_blacklisting_enabled and \
                    access_token_info['parentRefreshTokenHash1'] is None:
                ProcessState.update_service_called(False)
                return {
                    'session': {
                        'handle': access_token_info['sessionHandle'],
                        'userId': access_token_info['userId'],
                        'userDataInJWT': access_token_info['userData']
                    }
                }
    except SuperTokensTryRefreshTokenError:
        pass

    ProcessState.update_service_called(True)

    data = {
        'accessToken': access_token,
        'doAntiCsrfCheck': do_anti_csrf_check
    }
    if anti_csrf_token is not None:
        data['antiCsrfToken'] = anti_csrf_token

    response = await Querier.get_instance().send_post_request(SESSION_VERIFY, data)
    if response['status'] == 'OK':
        handshake_info = await HandshakeInfo.get_instance()
        handshake_info.update_jwt_signing_public_key_info(response['jwtSigningPublicKey'],
                                                          response['jwtSigningPublicKeyExpiryTime'])
        response.pop('status', None)
        response.pop('jwtSigningPublicKey', None)
        response.pop('jwtSigningPublicKeyExpiryTime', None)
        return response
    elif response['status'] == 'UNAUTHORISED':
        raise_unauthorised_exception(response['message'])
    else:
        raise_try_refresh_token_exception(response['message'])


async def refresh_session(refresh_token: str, anti_csrf_token: Union[str, None]):
    data = {
        'refreshToken': refresh_token
    }
    if anti_csrf_token is not None:
        data['antiCsrfToken'] = anti_csrf_token

    response = await Querier.get_instance().send_post_request(SESSION_REFRESH, data)
    if response['status'] == 'OK':
        response.pop('status', None)
        return response
    elif response['status'] == 'UNAUTHORISED':
        raise_unauthorised_exception(response['message'])
    else:
        raise_token_theft_exception(
            response['session']['userId'],
            response['session']['handle'])


async def revoke_all_sessions_for_user(user_id: str) -> List[str]:
    response = await Querier.get_instance().send_post_request(SESSION_REMOVE, {
        'userId': user_id
    })
    return response['sessionHandlesRevoked']


async def get_all_session_handles_for_user(user_id: str) -> List[str]:
    response = await Querier.get_instance().send_get_request(SESSION_USER, {
        'userId': user_id
    })
    return response['sessionHandles']


async def revoke_session(session_handle: str) -> bool:
    response = await Querier.get_instance().send_post_request(SESSION_REMOVE, {
        'sessionHandles': [session_handle]
    })
    return len(response['sessionHandlesRevoked']) == 1


async def revoke_multiple_sessions(session_handles: List[str]) -> List[str]:
    response = await Querier.get_instance().send_post_request(SESSION_REMOVE, {
        'sessionHandles': session_handles
    })
    return response['sessionHandlesRevoked']


async def get_session_data(session_handle: str) -> dict:
    response = await Querier.get_instance().send_get_request(SESSION_DATA, {
        'sessionHandle': session_handle
    })
    if response['status'] == 'OK':
        return response['userDataInDatabase']
    else:
        raise_unauthorised_exception(response['message'])


async def update_session_data(session_handle: str, new_session_data: dict):
    response = await Querier.get_instance().send_put_request(SESSION_DATA, {
        'sessionHandle': session_handle,
        'userDataInDatabase': new_session_data
    })
    if response['status'] == 'UNAUTHORISED':
        raise_unauthorised_exception(response['message'])


async def get_jwt_payload(session_handle: str) -> dict:
    response = await Querier.get_instance().send_get_request(JWT_DATA, {
        'sessionHandle': session_handle
    })
    if response['status'] == 'OK':
        return response['userDataInJWT']
    else:
        raise_unauthorised_exception(response['message'])


async def update_jwt_payload(session_handle: str, new_jwt_payload: dict):
    response = await Querier.get_instance().send_put_request(JWT_DATA, {
        'sessionHandle': session_handle,
        'userDataInJWT': new_jwt_payload
    })
    if response['status'] == 'UNAUTHORISED':
        raise_unauthorised_exception(response['message'])
