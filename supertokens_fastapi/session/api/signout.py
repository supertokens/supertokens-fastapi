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
from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from supertokens_fastapi.session.session_recipe import SessionRecipe
    from fastapi.requests import Request
from fastapi.responses import JSONResponse
from supertokens_fastapi.session.exceptions import UnauthorisedError
from supertokens_fastapi.exceptions import raise_general_exception


async def handle_signout_api(recipe: SessionRecipe, request: Request):
    try:
        session = await recipe.get_session(request)
    except UnauthorisedError:
        return JSONResponse({})

    if session is None:
        raise_general_exception(recipe, 'Session is undefined. Should not come here.')

    await session.revoke_session()

    return JSONResponse({})
