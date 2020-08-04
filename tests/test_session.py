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

from .utils import (
    reset, setup_st, clean_st, start_st, set_key_value_in_config,
    TEST_ENABLE_ANTI_CSRF_CONFIG_KEY
)
from supertokens_fastapi.session_helper import (
    get_all_session_handles_for_user,
    revoke_all_sessions_for_user,
    update_session_data,
    update_jwt_payload,
    create_new_session,
    get_session_data,
    get_jwt_payload,
    refresh_session,
    revoke_session,
    get_session,
    reset as s_reset,
    ProcessState
)
from supertokens_fastapi.exceptions import (
    SuperTokensTokenTheftError,
    SuperTokensUnauthorisedError,
    SuperTokensTryRefreshTokenError
)
from jsonschema import validate
from .schema import (
    session_with_anti_csrf,
    session_verify_with_access_token,
    session_verify_without_access_token
)
from pytest import mark


def setup_function(f):
    reset()
    clean_st()
    setup_st()


def teardown_function(f):
    reset()
    clean_st()


@mark.asyncio
async def test_token_theft_detection():
    start_st()
    session = await create_new_session('userId', {}, {})
    refreshed_session = await refresh_session(session['refreshToken']['token'])
    await get_session(refreshed_session['accessToken']['token'], refreshed_session['antiCsrfToken'], True)
    try:
        await refresh_session(session['refreshToken']['token'])
        assert False
    except SuperTokensTokenTheftError as e:
        assert e.user_id == 'userId'
        assert e.session_handle == session['session']['handle']
        assert True


@mark.asyncio
async def test_basic_usage_of_sessions():
    start_st()
    session = await create_new_session('userId', {}, {})
    validate(session, session_with_anti_csrf)

    await get_session(session['accessToken']['token'], session['antiCsrfToken'], True)
    assert not ProcessState.get_service_called()

    refreshed_session_1 = await refresh_session(session['refreshToken']['token'])
    validate(refreshed_session_1, session_with_anti_csrf)

    updated_session = await get_session(refreshed_session_1['accessToken']['token'],
                                        refreshed_session_1['antiCsrfToken'], True)
    assert ProcessState.get_service_called()
    validate(updated_session, session_verify_with_access_token)

    non_updated_session = await get_session(updated_session['accessToken']['token'],
                                            refreshed_session_1['antiCsrfToken'], True)
    assert not ProcessState.get_service_called()
    validate(non_updated_session, session_verify_without_access_token)

    assert await revoke_session(non_updated_session['session']['handle'])


@mark.asyncio
async def test_session_verify_with_anti_csrf():
    start_st()
    session = await create_new_session('userId', {}, {})

    session_get_1 = await get_session(session['accessToken']['token'], session['antiCsrfToken'], True)
    validate(session_get_1, session_verify_without_access_token)

    session_get_2 = await get_session(session['accessToken']['token'], session['antiCsrfToken'], False)
    validate(session_get_2, session_verify_without_access_token)


@mark.asyncio
async def test_session_verify_without_anti_csrf():
    start_st()
    session = await create_new_session('userId', {}, {})

    session_get_1 = await get_session(session['accessToken']['token'], None, False)
    validate(session_get_1, session_verify_without_access_token)

    try:
        await get_session(session['accessToken']['token'], None, True)
        assert False
    except SuperTokensTryRefreshTokenError:
        assert True


@mark.asyncio
async def test_revoking_of_session():
    start_st()
    await revoke_all_sessions_for_user('userId')
    assert len(await get_all_session_handles_for_user('userId')) == 0
    session = await create_new_session('userId', {}, {})
    assert len(await get_all_session_handles_for_user('userId')) == 1
    assert await revoke_session(session['session']['handle'])
    assert len(await get_all_session_handles_for_user('userId')) == 0
    await create_new_session('userId', {}, {})
    await create_new_session('userId', {}, {})
    assert len(await get_all_session_handles_for_user('userId')) == 2
    assert len(await revoke_all_sessions_for_user('userId')) == 2
    assert len(await get_all_session_handles_for_user('userId')) == 0
    s_reset()
    assert not await revoke_session('random')
    assert len(await revoke_all_sessions_for_user('randomUserId')) == 0


@mark.asyncio
async def test_manipulating_session_data():
    start_st()
    session = await create_new_session('userId', {}, {})
    session_data_1 = await get_session_data(session['session']['handle'])
    assert session_data_1 == {}
    await update_session_data(session['session']['handle'], {'key': 'value'})
    session_data_2 = await get_session_data(session['session']['handle'])
    assert session_data_2 == {'key': 'value'}
    await update_session_data(session['session']['handle'], {'key': 'new_value'})
    session_data_3 = await get_session_data(session['session']['handle'])
    assert session_data_3 == {'key': 'new_value'}
    try:
        await update_session_data('incorrect', {'key': 'value'})
        assert False
    except SuperTokensUnauthorisedError:
        assert True


@mark.asyncio
async def test_manipulating_jwt_data():
    start_st()
    session_1 = await create_new_session('userId', {}, {})
    session_2 = await create_new_session('userId', {}, {})
    session_data_1_1 = await get_jwt_payload(session_1['session']['handle'])
    assert session_data_1_1 == {}
    session_data_2_1 = await get_jwt_payload(session_2['session']['handle'])
    assert session_data_2_1 == {}

    await update_jwt_payload(session_1['session']['handle'], {'key': 'value'})
    session_data_1_2 = await get_jwt_payload(session_1['session']['handle'])
    assert session_data_1_2 == {'key': 'value'}
    session_data_2_2 = await get_jwt_payload(session_2['session']['handle'])
    assert session_data_2_2 == {}

    try:
        await update_jwt_payload('incorrect', {'key': 'value'})
        assert False
    except SuperTokensUnauthorisedError:
        assert True


@mark.asyncio
async def test_anti_csrf_disabled_for_core():
    set_key_value_in_config(TEST_ENABLE_ANTI_CSRF_CONFIG_KEY, False)
    start_st()
    session = await create_new_session('userId', {}, {})

    session_get_1 = await get_session(session['accessToken']['token'], None, False)
    validate(session_get_1, session_verify_without_access_token)

    session_get_2 = await get_session(session['accessToken']['token'], None, True)
    validate(session_get_2, session_verify_without_access_token)
