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
    from supertokens_fastapi.emailverification.recipe import EmailVerificationRecipe
    from fastapi.requests import Request
from fastapi.responses import JSONResponse
from supertokens_fastapi.exceptions import raise_general_exception
from supertokens_fastapi.session import verify_session
from supertokens_fastapi.emailverification.types import User


async def handle_generate_email_verify_token_api(recipe: EmailVerificationRecipe, request: Request):
    session = await verify_session()(request)
    if session is None:
        raise_general_exception(recipe, 'Session is undefined. Should not come here.')

    user_id = session.get_user_id()
    email = await recipe.config.get_email_for_user_id(user_id)

    token = await recipe.create_email_verification_token(user_id, email)
    user = User(user_id, email)

    email_verify_link = (await recipe.config.get_email_verification_url(user)) + '?token=' + token + '&rid' + recipe.get_recipe_id()

    try:
        await recipe.config.create_and_send_custom_email(user, email_verify_link)
    except Exception:
        pass
    return JSONResponse({
        'status': 'OK'
    })
