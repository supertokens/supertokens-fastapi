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
from typing import Union, TYPE_CHECKING, List
from .access_token import get_info_from_access_token
from .constants import (
    RECIPE_SESSION, RECIPE_SESSION_VERIFY, RECIPE_SESSION_REFRESH,
    RECIPE_SESSION_REMOVE, RECIPE_SESSION_USER, RECIPE_SESSION_DATA, RECIPE_JWT_DATA
)
if TYPE_CHECKING:
    from .session_recipe import SessionRecipe
from supertokens_fastapi.normalised_url_path import NormalisedURLPath
from supertokens_fastapi.utils import get_timestamp_ms
from .exceptions import (
    raise_try_refresh_token_exception,
    raise_unauthorised_exception,
    raise_token_theft_exception,
    TryRefreshTokenError
)
from supertokens_fastapi.process_state import AllowedProcessStates, ProcessState


async def create_new_session(recipe: SessionRecipe, user_id: str, jwt_payload: Union[dict, None] = None,
                             session_data: Union[dict, None] = None):
    if session_data is None:
        session_data = {}
    if jwt_payload is None:
        jwt_payload = {}

    handshake_info = await recipe.get_handshake_info()
    enable_anti_csrf = handshake_info.anti_csrf == 'VIA_TOKEN'
    response = await recipe.get_querier().send_post_request(NormalisedURLPath(recipe, RECIPE_SESSION), {
        'userId': user_id,
        'userDataInJWT': jwt_payload,
        'userDataInDatabase': session_data,
        'enableAntiCsrf': enable_anti_csrf
    })
    recipe.update_jwt_signing_public_key_info(response['jwtSigningPublicKey'],
                                              response['jwtSigningPublicKeyExpiryTime'])
    response.pop('status', None)
    response.pop('jwtSigningPublicKey', None)
    response.pop('jwtSigningPublicKeyExpiryTime', None)

    return response


async def get_session(recipe: SessionRecipe, access_token: str, anti_csrf_token: Union[str, None],
                      do_anti_csrf_check: bool, contains_custom_header: bool):
    handshake_info = await recipe.get_handshake_info()
    fallback_to_core = True
    try:
        if handshake_info.jwt_signing_public_key_expiry_time > get_timestamp_ms():
            access_token_info = get_info_from_access_token(recipe, access_token, handshake_info.jwt_signing_public_key,
                                                           handshake_info.anti_csrf == 'VIA_TOKEN' and do_anti_csrf_check)

            if handshake_info.anti_csrf == 'VIA_TOKEN' and do_anti_csrf_check:
                if anti_csrf_token is None or anti_csrf_token != access_token_info['antiCsrfToken']:
                    if anti_csrf_token is None:
                        raise_try_refresh_token_exception(recipe, 'Provided antiCsrfToken is undefined. If you do not '
                                                                  'want anti-csrf check for this API, please set '
                                                                  'doAntiCsrfCheck to false for this API')
                    else:
                        raise_try_refresh_token_exception(recipe, 'anti-csrf check failed')
            elif handshake_info.anti_csrf == 'VIA_CUSTOM_HEADER' and do_anti_csrf_check:
                if not contains_custom_header:
                    fallback_to_core = False
                    raise_try_refresh_token_exception(recipe, 'anti-csrf check failed. Please pass \'rid: "session"\' '
                                                              'header in the request, or set doAntiCsrfCheck to false '
                                                              'for this API')
            if not handshake_info.access_token_blacklisting_enabled and \
                    access_token_info['parentRefreshTokenHash1'] is None:
                return {
                    'session': {
                        'handle': access_token_info['sessionHandle'],
                        'userId': access_token_info['userId'],
                        'userDataInJWT': access_token_info['userData']
                    }
                }
    except TryRefreshTokenError:
        pass
    except Exception as e:
        if not fallback_to_core:
            raise e

    ProcessState.get_instance().add_state(AllowedProcessStates.CALLING_SERVICE_IN_VERIFY)
    data = {
        'accessToken': access_token,
        'doAntiCsrfCheck': do_anti_csrf_check
    }
    if anti_csrf_token is not None:
        data['antiCsrfToken'] = anti_csrf_token

    response = await recipe.get_querier().send_post_request(NormalisedURLPath(recipe, RECIPE_SESSION_VERIFY), data)
    if response['status'] == 'OK':
        handshake_info = await recipe.get_handshake_info()
        handshake_info.update_jwt_signing_public_key_info(response['jwtSigningPublicKey'],
                                                          response['jwtSigningPublicKeyExpiryTime'])
        response.pop('status', None)
        response.pop('jwtSigningPublicKey', None)
        response.pop('jwtSigningPublicKeyExpiryTime', None)
        return response
    elif response['status'] == 'UNAUTHORISED':
        raise_unauthorised_exception(recipe, response['message'])
    else:
        raise_try_refresh_token_exception(recipe, response['message'])


async def refresh_session(recipe: SessionRecipe, refresh_token: str, anti_csrf_token: Union[str, None],
                          contains_custom_header: bool):
    handshake_info = await recipe.get_handshake_info()
    data = {
        'refreshToken': refresh_token,
        'enableAntiCsrf': handshake_info.anti_csrf == 'VIA_TOKEN'
    }
    if anti_csrf_token is not None:
        data['antiCsrfToken'] = anti_csrf_token

    if handshake_info.anti_csrf == 'VIA_CUSTOM_HEADER':
        if not contains_custom_header:
            raise_try_refresh_token_exception(recipe, 'anti-csrf check failed. Please pass \'rid: "session"\' header '
                                              'in the request.')
    response = await recipe.get_querier().send_post_request(NormalisedURLPath(recipe, RECIPE_SESSION_REFRESH), data)
    if response['status'] == 'OK':
        response.pop('status', None)
        return response
    elif response['status'] == 'UNAUTHORISED':
        raise_unauthorised_exception(recipe, response['message'])
    else:
        raise_token_theft_exception(
            recipe,
            response['session']['userId'],
            response['session']['handle']
        )


async def revoke_all_sessions_for_user(recipe: SessionRecipe, user_id: str) -> List[str]:
    response = await recipe.get_querier().send_post_request(NormalisedURLPath(recipe, RECIPE_SESSION_REMOVE), {
        'userId': user_id
    })
    return response['sessionHandlesRevoked']


async def get_all_session_handles_for_user(recipe: SessionRecipe, user_id: str) -> List[str]:
    response = await recipe.get_querier().send_get_request(NormalisedURLPath(recipe, RECIPE_SESSION_USER), {
        'userId': user_id
    })
    return response['sessionHandles']


async def revoke_session(recipe: SessionRecipe, session_handle: str) -> bool:
    response = await recipe.get_querier().send_post_request(NormalisedURLPath(recipe, RECIPE_SESSION_REMOVE), {
        'sessionHandles': [session_handle]
    })
    return len(response['sessionHandlesRevoked']) == 1


async def revoke_multiple_sessions(recipe: SessionRecipe, session_handles: List[str]) -> List[str]:
    response = await recipe.get_querier().send_post_request(NormalisedURLPath(recipe, RECIPE_SESSION_REMOVE), {
        'sessionHandles': session_handles
    })
    return response['sessionHandlesRevoked']


async def get_session_data(recipe: SessionRecipe, session_handle: str) -> dict:
    response = await recipe.get_querier().send_get_request(NormalisedURLPath(recipe, RECIPE_SESSION_DATA), {
        'sessionHandle': session_handle
    })
    if response['status'] == 'OK':
        return response['userDataInDatabase']
    else:
        raise_unauthorised_exception(recipe, response['message'])


async def update_session_data(recipe: SessionRecipe, session_handle: str, new_session_data: dict):
    response = await recipe.get_querier().send_put_request(NormalisedURLPath(recipe, RECIPE_SESSION_DATA), {
        'sessionHandle': session_handle,
        'userDataInDatabase': new_session_data
    })
    if response['status'] == 'UNAUTHORISED':
        raise_unauthorised_exception(recipe, response['message'])


async def get_jwt_payload(recipe: SessionRecipe, session_handle: str) -> dict:
    response = await recipe.get_querier().send_get_request(NormalisedURLPath(recipe, RECIPE_JWT_DATA), {
        'sessionHandle': session_handle
    })
    if response['status'] == 'OK':
        return response['userDataInJWT']
    else:
        raise_unauthorised_exception(recipe, response['message'])


async def update_jwt_payload(recipe: SessionRecipe, session_handle: str, new_jwt_payload: dict):
    response = await recipe.get_querier().send_put_request(NormalisedURLPath(recipe, RECIPE_JWT_DATA), {
        'sessionHandle': session_handle,
        'userDataInJWT': new_jwt_payload
    })
    if response['status'] == 'UNAUTHORISED':
        raise_unauthorised_exception(recipe, response['message'])
