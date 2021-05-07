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
from .recipe import EmailVerificationRecipe
from . import exceptions


def init(config):
    return EmailVerificationRecipe.init(config)


async def create_email_verification_token(user_id: str, email: str):
    return await EmailVerificationRecipe.get_instance().create_email_verification_token(user_id, email)


async def verify_email_using_token(token: str):
    return await EmailVerificationRecipe.get_instance().verify_email_using_token(token)


async def is_email_verified(user_id: str, email: str):
    return await EmailVerificationRecipe.get_instance().is_email_verified(user_id, email)
