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
from typing import Union, List
from .session_class import Session
from .session_recipe import SessionRecipe
from .middleware import verify_session as original_verify_session
from fastapi.requests import Request
from . import exceptions


def init(config=None):
    return SessionRecipe.init(config)


async def create_new_session(request: Request, user_id: str, jwt_payload: Union[dict, None] = None,
                             session_data: Union[dict, None] = None) -> Session:
    return await SessionRecipe.get_instance().create_new_session(request, user_id, jwt_payload, session_data)


async def get_session(request: Request, anti_csrf_check: Union[bool, None] = None, session_required: bool = True) -> Union[Session, None]:
    return await SessionRecipe.get_instance().get_session(request, anti_csrf_check, session_required)


async def refresh_session(request: Request) -> Session:
    return await SessionRecipe.get_instance().refresh_session(request)


async def revoke_session(session_handle: str) -> bool:
    return await SessionRecipe.get_instance().revoke_session(session_handle)


async def revoke_all_sessions_for_user(user_id: str) -> List[str]:
    return await SessionRecipe.get_instance().revoke_all_sessions_for_user(user_id)


async def get_all_session_handles_for_user(user_id: str) -> List[str]:
    return await SessionRecipe.get_instance().get_all_session_handles_for_user(user_id)


async def revoke_multiple_sessions(session_handles: List[str]) -> List[str]:
    return await SessionRecipe.get_instance().revoke_multiple_sessions(session_handles)


async def get_session_data(session_handle: str) -> dict:
    return await SessionRecipe.get_instance().get_session_data(session_handle)


async def update_session_data(session_handle: str, new_session_data: dict) -> None:
    return await SessionRecipe.get_instance().update_session_data(session_handle, new_session_data)


async def get_jwt_payload(session_handle: str) -> dict:
    return await SessionRecipe.get_instance().get_jwt_payload(session_handle)


async def update_jwt_payload(session_handle: str, new_jwt_payload: dict) -> None:
    return await SessionRecipe.get_instance().update_jwt_payload(session_handle, new_jwt_payload)


def verify_session(anti_csrf_check: Union[bool, None] = None, session_required: bool = True):
    return original_verify_session(SessionRecipe.get_instance(), anti_csrf_check, session_required)
