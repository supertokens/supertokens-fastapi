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

from fastapi.responses import JSONResponse
from supertokens_fastapi.handshake_info import HandshakeInfo
from supertokens_fastapi.constants import ERROR_MESSAGE_KEY
from supertokens_fastapi.session_helper import revoke_session


async def default_unauthorised_callback(e):
    return JSONResponse(
        status_code=(await HandshakeInfo.get_instance()).session_expired_status_code,
        content={ERROR_MESSAGE_KEY: 'unauthorised'}
    )


async def default_try_refresh_token_callback(e):
    return JSONResponse(
        status_code=(await HandshakeInfo.get_instance()).session_expired_status_code,
        content={ERROR_MESSAGE_KEY: 'try refresh token'}
    )


async def default_token_theft_detected_callback(session_handle, user_id):
    await revoke_session(session_handle)
    return JSONResponse(
        status_code=(await HandshakeInfo.get_instance()).session_expired_status_code,
        content={ERROR_MESSAGE_KEY: 'token theft detected'}
    )
