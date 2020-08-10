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

from .supertokens import (
    SuperTokens,
    Session,
    auth0_handler,
    supertokens_session,
    supertokens_session_with_anti_csrf,
    supertokens_session_without_anti_csrf,
    get_session,
    revoke_session,
    refresh_session,
    get_jwt_payload,
    get_session_data,
    create_new_session,
    update_jwt_payload,
    update_session_data,
    revoke_multiple_sessions,
    revoke_all_sessions_for_user,
    set_relevant_headers_for_options_api,
    get_all_session_handles_for_user,
    get_cors_allowed_headers
)
from . import exceptions
