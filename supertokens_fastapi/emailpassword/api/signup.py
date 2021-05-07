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
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from supertokens_fastapi.emailpassword.recipe import EmailPasswordRecipe
    from fastapi.requests import Request
from fastapi.responses import JSONResponse
from .utils import validate_form_fields_or_throw_error
from supertokens_fastapi.emailpassword.constants import FORM_FIELD_PASSWORD_ID, FORM_FIELD_EMAIL_ID
from supertokens_fastapi.utils import find_first_occurrence_in_list, get_filtered_list
from supertokens_fastapi.exceptions import raise_general_exception
from supertokens_fastapi.session import create_new_session


async def handle_sign_up_api(recipe: EmailPasswordRecipe, request: Request):
    body = await request.json()
    form_fields_raw = body['formFields'] if 'formFields' in body else []
    form_fields = await validate_form_fields_or_throw_error(recipe,
                                                            recipe.config.sign_in_feature.form_fields,
                                                            form_fields_raw)
    password = find_first_occurrence_in_list(lambda x: x.id == FORM_FIELD_PASSWORD_ID, form_fields).value
    email = find_first_occurrence_in_list(lambda x: x.id == FORM_FIELD_EMAIL_ID, form_fields).value

    user = await recipe.sign_up(email, password)

    await recipe.config.sign_in_feature.handle_post_sign_up(user, get_filtered_list(
        lambda x: x.id != FORM_FIELD_EMAIL_ID and x.id != FORM_FIELD_PASSWORD_ID, form_fields))

    jwt_payload_promise = recipe.config.session_feature.set_jwt_payload(user, get_filtered_list(
        lambda x: x.id != FORM_FIELD_EMAIL_ID and x.id != FORM_FIELD_PASSWORD_ID, form_fields), 'signin')
    session_data_promise = recipe.config.session_feature.set_session_data(user, get_filtered_list(
        lambda x: x.id != FORM_FIELD_EMAIL_ID and x.id != FORM_FIELD_PASSWORD_ID, form_fields), 'signin')

    jwt_payload = {}
    session_data = {}
    try:
        jwt_payload = await jwt_payload_promise
        session_data = await session_data_promise
    except Exception as e:
        raise_general_exception(recipe, e)

    await create_new_session(request, user.id, jwt_payload, session_data)

    return JSONResponse({
        'status': 'OK',
        'user': {
            'id': user.id,
            'email': user.email,
            'timeJoined': user.timeJoined
        }
    })
