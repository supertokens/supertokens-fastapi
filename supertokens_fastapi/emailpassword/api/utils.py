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
from __future__ import annotations
from typing import TYPE_CHECKING, List
if TYPE_CHECKING:
    from supertokens_fastapi.emailpassword.recipe import EmailPasswordRecipe
    from supertokens_fastapi.emailpassword.types import NormalisedFormField
from supertokens_fastapi.emailpassword.types import FormField, ErrorFormField
from supertokens_fastapi.emailpassword.constants import FORM_FIELD_EMAIL_ID
from supertokens_fastapi.exceptions import raise_bad_input_exception
from supertokens_fastapi.utils import find_first_occurrence_in_list
from supertokens_fastapi.emailpassword.exceptions import raise_form_field_exception


async def validate_form_or_throw_error(recipe: EmailPasswordRecipe, inputs: List[FormField], config_form_fields: List[NormalisedFormField]):
    validation_errors: List[ErrorFormField] = []
    if len(config_form_fields) != len(inputs):
        raise_bad_input_exception(recipe, 'Are you sending too many / too few formFields?')

    for field in config_form_fields:
        input_field: FormField = find_first_occurrence_in_list(lambda x: x.id == field.id, inputs)
        if input_field is None or (input_field.value == '' and not field.optional):
            validation_errors.append(ErrorFormField(field.id, 'Field is not optional'))
        else:
            error = await field.validate(input_field.value)
            if error is not None:
                validation_errors.append(ErrorFormField(field.id, error))

    if len(validation_errors) != 0:
        raise_form_field_exception(recipe, 'Error in input formFields', validation_errors)


async def validate_form_fields_or_throw_error(recipe: EmailPasswordRecipe, config_form_fields: List[NormalisedFormField], form_fields_raw: any) -> List[FormField]:
    if form_fields_raw is None:
        raise_bad_input_exception(recipe, 'Missing input param: formFields')

    if not isinstance(form_fields_raw, list):
        raise_bad_input_exception(recipe, 'formFields must be an array')

    form_fields: List[FormField] = []

    for current_form_field in form_fields_raw:
        if 'id' not in current_form_field or not isinstance(current_form_field['id'],
                                                            str) or 'value' not in current_form_field:
            raise_bad_input_exception(recipe, 'All elements of formFields must contain an \'id\' and \'value\' field')
        value = current_form_field['value']
        id = current_form_field['id']
        if id == FORM_FIELD_EMAIL_ID:
            value = value.strip()
        form_fields.append(FormField(id, value))

    await validate_form_or_throw_error(recipe, form_fields, config_form_fields)
    return form_fields
