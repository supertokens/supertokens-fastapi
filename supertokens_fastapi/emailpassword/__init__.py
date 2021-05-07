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
from .recipe import EmailPasswordRecipe
from . import exceptions


def init(config=None):
    return EmailPasswordRecipe.init(config)


async def create_email_verification_token(user_id: str):
    return await EmailPasswordRecipe.get_instance().create_email_verification_token(user_id)


async def verify_email_using_token(token: str):
    return await EmailPasswordRecipe.get_instance().verify_email_using_token(token)


async def is_email_verified(user_id: str):
    return await EmailPasswordRecipe.get_instance().is_email_verified(user_id)


async def get_users_oldest_first(limit: int = None, next_pagination: str = None):
    return await EmailPasswordRecipe.get_instance().get_users_oldest_first(limit, next_pagination)


async def get_users_newest_first(limit: int = None, next_pagination: str = None):
    return await EmailPasswordRecipe.get_instance().get_users_newest_first(limit, next_pagination)


async def get_user_count():
    return await EmailPasswordRecipe.get_instance().get_user_count()


async def get_user_by_id(user_id: str):
    return await EmailPasswordRecipe.get_instance().get_user_by_id(user_id)


async def get_user_by_email(email: str):
    return await EmailPasswordRecipe.get_instance().get_user_by_email(email)


async def create_reset_password_token(user_id: str):
    return await EmailPasswordRecipe.get_instance().create_reset_password_token(user_id)


async def reset_password_using_token(token: str, new_password: str):
    return await EmailPasswordRecipe.get_instance().reset_password_using_token(token, new_password)


async def sign_in(email: str, password: str):
    return await EmailPasswordRecipe.get_instance().sign_in(email, password)


async def sign_up(email: str, password: str):
    return await EmailPasswordRecipe.get_instance().sign_up(email, password)
