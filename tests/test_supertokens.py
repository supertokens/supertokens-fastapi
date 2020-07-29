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
from supertokens_fastapi.exceptions import SuperTokensUnauthorisedError
from .utils import (
    reset, setup_st, clean_st, start_st, set_key_value_in_config,
    get_unix_timestamp, extract_all_cookies,
    TEST_ENABLE_ANTI_CSRF_CONFIG_KEY,
    TEST_ACCESS_TOKEN_PATH_VALUE,
    TEST_ACCESS_TOKEN_PATH_CONFIG_KEY,
    TEST_REFRESH_TOKEN_PATH_KEY_VALUE,
    TEST_REFRESH_TOKEN_PATH_CONFIG_KEY,
    TEST_COOKIE_DOMAIN_VALUE,
    TEST_COOKIE_DOMAIN_CONFIG_KEY,
    TEST_ACCESS_TOKEN_MAX_AGE_VALUE,
    TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY,
    TEST_REFRESH_TOKEN_MAX_AGE_VALUE,
    TEST_REFRESH_TOKEN_MAX_AGE_CONFIG_KEY,
    TEST_COOKIE_SAME_SITE_VALUE,
    TEST_COOKIE_SAME_SITE_CONFIG_KEY,
    TEST_COOKIE_SECURE_VALUE,
    TEST_COOKIE_SECURE_CONFIG_KEY,
    TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH,
    TEST_DRIVER_CONFIG_COOKIE_DOMAIN,
    TEST_DRIVER_CONFIG_COOKIE_SAME_SITE,
    TEST_DRIVER_CONFIG_COOKIE_SECURE,
    TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH,
    ACCESS_CONTROL_EXPOSE_HEADER,
    ACCESS_CONTROL_EXPOSE_HEADER_ANTI_CSRF_ENABLE,
    ACCESS_CONTROL_EXPOSE_HEADER_ANTI_CSRF_DISABLE
)
from supertokens_fastapi.supertokens import (
    set_relevant_headers_for_options_api,
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
    SuperTokens
)
from supertokens_fastapi.session_helper import ProcessState
from time import time
from pytest import fixture
from flask import request, Flask, jsonify, make_response, Response
from supertokens_fastapi.constants import (
    COOKIE_SECURE_CONFIG,
    COOKIE_SAME_SITE_CONFIG,
    COOKIE_DOMAIN_CONFIG,
    ACCESS_TOKEN_PATH_CONFIG,
    REFRESH_TOKEN_PATH_CONFIG
)


def setup_function(f):
    reset()
    clean_st()
    setup_st()


def teardown_function(f):
    reset()
    clean_st()


@fixture(scope='function')
def app():
    app = Flask(__name__)
    app.config[COOKIE_DOMAIN_CONFIG] = 'supertokens.io'
    supertokens = SuperTokens(app)

    def ff(e):
        return jsonify({'error_msg': 'try refresh token'}), 401

    supertokens.set_try_refresh_token_error_handler(ff)

    @app.route('/login')
    def login():
        user_id = 'userId'
        response = make_response(jsonify({'userId': user_id}), 200)
        create_new_session(response, user_id, {}, {})
        return response

    @app.route('/refresh', methods=['POST'])
    def refresh():
        response = make_response(jsonify({}))
        refresh_session(response)
        return response

    @app.route('/info', methods=['GET', 'OPTIONS'])
    def info():
        if request.method == 'OPTIONS':
            return jsonify({'method': 'option'})
        response = make_response(jsonify({}))
        get_session(response, True)
        return response

    @app.route('/handle', methods=['GET', 'OPTIONS'])
    def handle_api():
        if request.method == 'OPTIONS':
            return jsonify({'method': 'option'})
        session = get_session(None, False)
        return jsonify({'s': session.get_handle()})

    @app.route('/logout', methods=['POST'])
    def logout():
        response = make_response(jsonify({}))
        supertokens_session = get_session(response, True)
        supertokens_session.revoke_session()
        return response

    return app


@fixture(scope='function')
def driver_config_app():
    app = Flask(__name__)
    app.config[COOKIE_DOMAIN_CONFIG] = TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    app.config[ACCESS_TOKEN_PATH_CONFIG] = TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    app.config[REFRESH_TOKEN_PATH_CONFIG] = TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    app.config[COOKIE_SAME_SITE_CONFIG] = TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    app.config[COOKIE_SECURE_CONFIG] = TEST_DRIVER_CONFIG_COOKIE_SECURE
    supertokens = SuperTokens(app)

    def ff(e):
        return jsonify({'error_msg': 'try refresh token'}), 401

    supertokens.set_try_refresh_token_error_handler(ff)

    @app.route('/login')
    def login():
        user_id = 'userId'
        response = make_response(jsonify({'userId': user_id}), 200)
        create_new_session(response, user_id, {}, {})
        return response

    @app.route('/custom/refresh', methods=['POST'])
    def custom_refresh():
        response = make_response(jsonify({}))
        refresh_session(response)
        return response

    @app.route('/custom/info', methods=['GET', 'OPTIONS'])
    def custom_info():
        if request.method == 'OPTIONS':
            return jsonify({'method': 'option'})
        response = make_response(jsonify({}))
        get_session(response, True)
        return response

    @app.route('/custom/handle', methods=['GET', 'OPTIONS'])
    def custom_handle_api():
        if request.method == 'OPTIONS':
            return jsonify({'method': 'option'})
        session = get_session(None, False)
        return jsonify({'s': session.get_handle()})

    @app.route('/custom/logout', methods=['POST'])
    def custom_logout():
        response = make_response(jsonify({}))
        supertokens_session = get_session(response, True)
        supertokens_session.revoke_session()
        return response
    return app


@fixture(scope='function')
def core_config_app():
    app = Flask(__name__)

    supertokens = SuperTokens(app)

    def ff(e):
        return jsonify({'error_msg': 'try refresh token'}), 401

    supertokens.set_try_refresh_token_error_handler(ff)

    @app.route('/login')
    def login():
        user_id = 'userId'
        response = make_response(jsonify({'userId': user_id}), 200)
        create_new_session(response, user_id, {}, {})
        return response

    @app.route('/refresh', methods=['POST'])
    def refresh():
        response = make_response(jsonify({}))
        refresh_session(response)
        return response

    @app.route('/info', methods=['GET', 'OPTIONS'])
    def info():
        if request.method == 'OPTIONS':
            return jsonify({'method': 'option'})
        response = make_response(jsonify({}))
        get_session(response, True)
        return response

    @app.route('/handle', methods=['GET', 'OPTIONS'])
    def handle_api():
        if request.method == 'OPTIONS':
            return jsonify({'method': 'option'})
        session = get_session(None, False)
        return jsonify({'s': session.get_handle()})

    @app.route('/logout', methods=['POST'])
    def logout():
        response = make_response(jsonify({}))
        supertokens_session = get_session(response, True)
        supertokens_session.revoke_session()
        return response

    return app


def test_cookie_and_header_values_with_driver_config_and_csrf_enabled(driver_config_app):
    set_key_value_in_config(
        TEST_COOKIE_SAME_SITE_CONFIG_KEY,
        'None')
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY,
        TEST_ACCESS_TOKEN_MAX_AGE_VALUE)
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_PATH_CONFIG_KEY,
        TEST_ACCESS_TOKEN_PATH_VALUE)
    set_key_value_in_config(
        TEST_COOKIE_DOMAIN_CONFIG_KEY,
        TEST_COOKIE_DOMAIN_VALUE)
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_MAX_AGE_CONFIG_KEY,
        TEST_REFRESH_TOKEN_MAX_AGE_VALUE)
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_PATH_CONFIG_KEY,
        TEST_REFRESH_TOKEN_PATH_KEY_VALUE)
    set_key_value_in_config(
        TEST_COOKIE_SECURE_CONFIG_KEY,
        False)
    start_st()

    response_1 = driver_config_app.test_client().get('/login')
    cookies_1 = extract_all_cookies(response_1)

    assert response_1.headers.get('anti-csrf') is not None
    assert cookies_1['sAccessToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1['sRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1['sIdRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1['sAccessToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1['sRefreshToken']['path'] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_1['sIdRefreshToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1['sAccessToken']['httponly']
    assert cookies_1['sRefreshToken']['httponly']
    assert cookies_1['sIdRefreshToken']['httponly']
    assert cookies_1['sAccessToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_1['sRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_1['sIdRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_1['sAccessToken']['secure']
    assert cookies_1['sRefreshToken']['secure']
    assert cookies_1['sIdRefreshToken']['secure']
    assert get_unix_timestamp(
        cookies_1['sAccessToken']['expires']) - int(time()) in {
            TEST_ACCESS_TOKEN_MAX_AGE_VALUE,
            TEST_ACCESS_TOKEN_MAX_AGE_VALUE - 1
    }
    assert get_unix_timestamp(cookies_1['sRefreshToken']['expires']) - int(time()) == \
        TEST_REFRESH_TOKEN_MAX_AGE_VALUE * 60
    assert cookies_1['sIdRefreshToken']['value'] + \
        ';' == response_1.headers['Id-Refresh-Token'][:-13]
    assert int(response_1.headers['Id-Refresh-Token'][-13:-3]) == \
        get_unix_timestamp(cookies_1['sIdRefreshToken']['expires'])
    assert response_1.headers[ACCESS_CONTROL_EXPOSE_HEADER] == ACCESS_CONTROL_EXPOSE_HEADER_ANTI_CSRF_ENABLE

    request_2 = driver_config_app.test_client()
    request_2.set_cookie(
        'localhost',
        'sRefreshToken',
        cookies_1['sRefreshToken']['value'])
    response_2 = request_2.post('/custom/refresh')
    cookies_2 = extract_all_cookies(response_2)
    assert cookies_1['sAccessToken']['value'] != cookies_2['sAccessToken']['value']
    assert cookies_1['sRefreshToken']['value'] != cookies_2['sRefreshToken']['value']
    assert cookies_1['sIdRefreshToken']['value'] != cookies_2['sIdRefreshToken']['value']
    assert response_2.headers.get('anti-csrf') is not None
    assert cookies_2['sAccessToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2['sRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2['sIdRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2['sAccessToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_2['sRefreshToken']['path'] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_2['sIdRefreshToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_2['sAccessToken']['httponly']
    assert cookies_2['sRefreshToken']['httponly']
    assert cookies_2['sIdRefreshToken']['httponly']
    assert cookies_2['sAccessToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_2['sRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_2['sIdRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_2['sAccessToken']['secure']
    assert cookies_2['sRefreshToken']['secure']
    assert cookies_2['sIdRefreshToken']['secure']
    assert get_unix_timestamp(
        cookies_2['sAccessToken']['expires']) - int(time()) == TEST_ACCESS_TOKEN_MAX_AGE_VALUE
    assert get_unix_timestamp(cookies_2['sRefreshToken']['expires']) - int(time()) == \
        TEST_REFRESH_TOKEN_MAX_AGE_VALUE * 60
    assert cookies_2['sIdRefreshToken']['value'] + \
        ';' == response_2.headers['Id-Refresh-Token'][:-13]
    assert int(response_2.headers['Id-Refresh-Token'][-13:-3]) == \
        get_unix_timestamp(cookies_2['sIdRefreshToken']['expires'])
    assert response_2.headers[ACCESS_CONTROL_EXPOSE_HEADER] == ACCESS_CONTROL_EXPOSE_HEADER_ANTI_CSRF_ENABLE

    request_3 = driver_config_app.test_client()
    request_3.set_cookie(
        'localhost',
        'sAccessToken',
        cookies_2['sAccessToken']['value'])
    request_3.set_cookie(
        'localhost',
        'sIdRefreshToken',
        cookies_2['sIdRefreshToken']['value'])
    response_3 = request_3.get(
        '/custom/info',
        headers={
            'anti-csrf': response_2.headers.get('anti-csrf')})
    assert response_3.status_code == 200
    cookies_3 = extract_all_cookies(response_3)
    assert cookies_3['sAccessToken']['value'] != cookies_2['sAccessToken']['value']
    assert response_3.headers.get('anti-csrf') is None
    assert cookies_3.get('sRefreshToken') is None
    assert cookies_3.get('sIdRefreshToken') is None
    assert cookies_3['sAccessToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_3['sAccessToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_3['sAccessToken']['httponly']
    assert cookies_3['sAccessToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_3['sAccessToken']['secure']

    request_4 = driver_config_app.test_client()
    request_4.set_cookie(
        'localhost',
        'sAccessToken',
        cookies_3['sAccessToken']['value'])
    request_4.set_cookie(
        'localhost',
        'sIdRefreshToken',
        cookies_2['sIdRefreshToken']['value'])
    response_4 = request_4.post(
        '/custom/logout',
        headers={
            'anti-csrf': response_2.headers.get('anti-csrf')})
    cookies_4 = extract_all_cookies(response_4)
    assert response_4.headers.get('anti-csrf') is None
    assert cookies_4['sAccessToken']['value'] == ''
    assert cookies_4['sRefreshToken']['value'] == ''
    assert cookies_4['sIdRefreshToken']['value'] == ''
    assert cookies_4['sAccessToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_4['sRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_4['sIdRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_4['sAccessToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_4['sRefreshToken']['path'] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_4['sIdRefreshToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_4['sAccessToken']['httponly']
    assert cookies_4['sRefreshToken']['httponly']
    assert cookies_4['sIdRefreshToken']['httponly']
    assert cookies_4['sAccessToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_4['sRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_4['sIdRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_4['sAccessToken']['secure']
    assert cookies_4['sRefreshToken']['secure']
    assert cookies_4['sIdRefreshToken']['secure']
    assert get_unix_timestamp(cookies_4['sAccessToken']['expires']) == 0
    assert get_unix_timestamp(cookies_4['sRefreshToken']['expires']) == 0
    assert get_unix_timestamp(cookies_4['sIdRefreshToken']['expires']) == 0
    assert response_4.headers['Id-Refresh-Token'] == 'remove'


def test_cookie_and_header_values_with_driver_config_and_csrf_disabled(driver_config_app):
    set_key_value_in_config(TEST_ENABLE_ANTI_CSRF_CONFIG_KEY, False)
    set_key_value_in_config(
        TEST_COOKIE_SAME_SITE_CONFIG_KEY,
        'None')
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY,
        TEST_ACCESS_TOKEN_MAX_AGE_VALUE)
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_PATH_CONFIG_KEY,
        TEST_ACCESS_TOKEN_PATH_VALUE)
    set_key_value_in_config(
        TEST_COOKIE_DOMAIN_CONFIG_KEY,
        TEST_COOKIE_DOMAIN_VALUE)
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_MAX_AGE_CONFIG_KEY,
        TEST_REFRESH_TOKEN_MAX_AGE_VALUE)
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_PATH_CONFIG_KEY,
        TEST_REFRESH_TOKEN_PATH_KEY_VALUE)
    set_key_value_in_config(
        TEST_COOKIE_SECURE_CONFIG_KEY,
        False)
    start_st()

    response_1 = driver_config_app.test_client().get('/login')
    cookies_1 = extract_all_cookies(response_1)

    assert response_1.headers.get('anti-csrf') is None
    assert cookies_1['sAccessToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1['sRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1['sIdRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_1['sAccessToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1['sRefreshToken']['path'] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_1['sIdRefreshToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_1['sAccessToken']['httponly']
    assert cookies_1['sRefreshToken']['httponly']
    assert cookies_1['sIdRefreshToken']['httponly']
    assert cookies_1['sAccessToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_1['sRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_1['sIdRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_1['sAccessToken']['secure']
    assert cookies_1['sRefreshToken']['secure']
    assert cookies_1['sIdRefreshToken']['secure']
    assert get_unix_timestamp(
        cookies_1['sAccessToken']['expires']) - int(time()) in {
            TEST_ACCESS_TOKEN_MAX_AGE_VALUE,
            TEST_ACCESS_TOKEN_MAX_AGE_VALUE - 1
    }
    assert get_unix_timestamp(cookies_1['sRefreshToken']['expires']) - int(time()) == \
        TEST_REFRESH_TOKEN_MAX_AGE_VALUE * 60
    assert cookies_1['sIdRefreshToken']['value'] + \
        ';' == response_1.headers['Id-Refresh-Token'][:-13]
    assert int(response_1.headers['Id-Refresh-Token'][-13:-3]) == \
        get_unix_timestamp(cookies_1['sIdRefreshToken']['expires'])
    assert response_1.headers[ACCESS_CONTROL_EXPOSE_HEADER] == ACCESS_CONTROL_EXPOSE_HEADER_ANTI_CSRF_DISABLE

    request_2 = driver_config_app.test_client()
    request_2.set_cookie(
        'localhost',
        'sRefreshToken',
        cookies_1['sRefreshToken']['value'])
    response_2 = request_2.post('/custom/refresh')
    cookies_2 = extract_all_cookies(response_2)
    assert cookies_1['sAccessToken']['value'] != cookies_2['sAccessToken']['value']
    assert cookies_1['sRefreshToken']['value'] != cookies_2['sRefreshToken']['value']
    assert cookies_1['sIdRefreshToken']['value'] != cookies_2['sIdRefreshToken']['value']
    assert response_2.headers.get('anti-csrf') is None
    assert cookies_2['sAccessToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2['sRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2['sIdRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_2['sAccessToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_2['sRefreshToken']['path'] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_2['sIdRefreshToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_2['sAccessToken']['httponly']
    assert cookies_2['sRefreshToken']['httponly']
    assert cookies_2['sIdRefreshToken']['httponly']
    assert cookies_2['sAccessToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_2['sRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_2['sIdRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_2['sAccessToken']['secure']
    assert cookies_2['sRefreshToken']['secure']
    assert cookies_2['sIdRefreshToken']['secure']
    assert get_unix_timestamp(
        cookies_2['sAccessToken']['expires']) - int(time()) == TEST_ACCESS_TOKEN_MAX_AGE_VALUE
    assert get_unix_timestamp(cookies_2['sRefreshToken']['expires']) - int(time()) == \
        TEST_REFRESH_TOKEN_MAX_AGE_VALUE * 60
    assert cookies_2['sIdRefreshToken']['value'] + \
        ';' == response_2.headers['Id-Refresh-Token'][:-13]
    assert int(response_2.headers['Id-Refresh-Token'][-13:-3]) == \
        get_unix_timestamp(cookies_2['sIdRefreshToken']['expires'])
    assert response_2.headers[ACCESS_CONTROL_EXPOSE_HEADER] == ACCESS_CONTROL_EXPOSE_HEADER_ANTI_CSRF_DISABLE

    request_3 = driver_config_app.test_client()
    request_3.set_cookie(
        'localhost',
        'sAccessToken',
        cookies_2['sAccessToken']['value'])
    request_3.set_cookie(
        'localhost',
        'sIdRefreshToken',
        cookies_2['sIdRefreshToken']['value'])
    response_3 = request_3.get('/custom/info')
    assert response_3.status_code == 200
    cookies_3 = extract_all_cookies(response_3)
    assert cookies_3['sAccessToken']['value'] != cookies_2['sAccessToken']['value']
    assert response_3.headers.get('anti-csrf') is None
    assert cookies_3.get('sRefreshToken') is None
    assert cookies_3.get('sIdRefreshToken') is None
    assert cookies_3['sAccessToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_3['sAccessToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_3['sAccessToken']['httponly']
    assert cookies_3['sAccessToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_3['sAccessToken']['secure']

    request_4 = driver_config_app.test_client()
    request_4.set_cookie(
        'localhost',
        'sAccessToken',
        cookies_3['sAccessToken']['value'])
    request_4.set_cookie(
        'localhost',
        'sIdRefreshToken',
        cookies_2['sIdRefreshToken']['value'])
    response_4 = request_4.post('/custom/logout')
    cookies_4 = extract_all_cookies(response_4)
    assert response_4.headers.get('anti-csrf') is None
    assert cookies_4['sAccessToken']['value'] == ''
    assert cookies_4['sRefreshToken']['value'] == ''
    assert cookies_4['sIdRefreshToken']['value'] == ''
    assert cookies_4['sAccessToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_4['sRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_4['sIdRefreshToken']['domain'] == TEST_DRIVER_CONFIG_COOKIE_DOMAIN
    assert cookies_4['sAccessToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_4['sRefreshToken']['path'] == TEST_DRIVER_CONFIG_REFRESH_TOKEN_PATH
    assert cookies_4['sIdRefreshToken']['path'] == TEST_DRIVER_CONFIG_ACCESS_TOKEN_PATH
    assert cookies_4['sAccessToken']['httponly']
    assert cookies_4['sRefreshToken']['httponly']
    assert cookies_4['sIdRefreshToken']['httponly']
    assert cookies_4['sAccessToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_4['sRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_4['sIdRefreshToken']['samesite'] == TEST_DRIVER_CONFIG_COOKIE_SAME_SITE
    assert cookies_4['sAccessToken']['secure']
    assert cookies_4['sRefreshToken']['secure']
    assert cookies_4['sIdRefreshToken']['secure']
    assert get_unix_timestamp(cookies_4['sAccessToken']['expires']) == 0
    assert get_unix_timestamp(cookies_4['sRefreshToken']['expires']) == 0
    assert get_unix_timestamp(cookies_4['sIdRefreshToken']['expires']) == 0
    assert response_4.headers['Id-Refresh-Token'] == 'remove'


def test_cookie_and_header_values_with_csrf_enabled(core_config_app):
    set_key_value_in_config(
        TEST_COOKIE_SAME_SITE_CONFIG_KEY,
        TEST_COOKIE_SAME_SITE_VALUE)
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY,
        TEST_ACCESS_TOKEN_MAX_AGE_VALUE)
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_PATH_CONFIG_KEY,
        TEST_ACCESS_TOKEN_PATH_VALUE)
    set_key_value_in_config(
        TEST_COOKIE_DOMAIN_CONFIG_KEY,
        TEST_COOKIE_DOMAIN_VALUE)
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_MAX_AGE_CONFIG_KEY,
        TEST_REFRESH_TOKEN_MAX_AGE_VALUE)
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_PATH_CONFIG_KEY,
        TEST_REFRESH_TOKEN_PATH_KEY_VALUE)
    set_key_value_in_config(
        TEST_COOKIE_SECURE_CONFIG_KEY,
        TEST_COOKIE_SECURE_VALUE)
    start_st()

    response_1 = core_config_app.test_client().get('/login')
    cookies_1 = extract_all_cookies(response_1)

    assert response_1.headers.get('anti-csrf') is not None
    assert cookies_1['sAccessToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
    assert cookies_1['sRefreshToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
    assert cookies_1['sIdRefreshToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
    assert cookies_1['sAccessToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
    assert cookies_1['sRefreshToken']['path'] == TEST_REFRESH_TOKEN_PATH_KEY_VALUE
    assert cookies_1['sIdRefreshToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
    assert cookies_1['sAccessToken']['httponly']
    assert cookies_1['sRefreshToken']['httponly']
    assert cookies_1['sIdRefreshToken']['httponly']
    assert cookies_1['sAccessToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
    assert cookies_1['sRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
    assert cookies_1['sIdRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
    assert cookies_1['sAccessToken']['secure']
    assert cookies_1['sRefreshToken']['secure']
    assert cookies_1['sIdRefreshToken']['secure']
    assert get_unix_timestamp(
        cookies_1['sAccessToken']['expires']) - int(time()) in {
            TEST_ACCESS_TOKEN_MAX_AGE_VALUE,
            TEST_ACCESS_TOKEN_MAX_AGE_VALUE - 1
    }
    assert get_unix_timestamp(cookies_1['sRefreshToken']['expires']) - int(time()) == \
        TEST_REFRESH_TOKEN_MAX_AGE_VALUE * 60
    assert cookies_1['sIdRefreshToken']['value'] + \
        ';' == response_1.headers['Id-Refresh-Token'][:-13]
    assert int(response_1.headers['Id-Refresh-Token'][-13:-3]) == \
        get_unix_timestamp(cookies_1['sIdRefreshToken']['expires'])
    assert response_1.headers[ACCESS_CONTROL_EXPOSE_HEADER] == ACCESS_CONTROL_EXPOSE_HEADER_ANTI_CSRF_ENABLE

    request_2 = core_config_app.test_client()
    request_2.set_cookie(
        'localhost',
        'sRefreshToken',
        cookies_1['sRefreshToken']['value'])
    response_2 = request_2.post('/refresh')
    cookies_2 = extract_all_cookies(response_2)
    assert cookies_1['sAccessToken']['value'] != cookies_2['sAccessToken']['value']
    assert cookies_1['sRefreshToken']['value'] != cookies_2['sRefreshToken']['value']
    assert cookies_1['sIdRefreshToken']['value'] != cookies_2['sIdRefreshToken']['value']
    assert response_2.headers.get('anti-csrf') is not None
    assert cookies_2['sAccessToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
    assert cookies_2['sRefreshToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
    assert cookies_2['sIdRefreshToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
    assert cookies_2['sAccessToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
    assert cookies_2['sRefreshToken']['path'] == TEST_REFRESH_TOKEN_PATH_KEY_VALUE
    assert cookies_2['sIdRefreshToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
    assert cookies_2['sAccessToken']['httponly']
    assert cookies_2['sRefreshToken']['httponly']
    assert cookies_2['sIdRefreshToken']['httponly']
    assert cookies_2['sAccessToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
    assert cookies_2['sRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
    assert cookies_2['sIdRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
    assert cookies_2['sAccessToken']['secure']
    assert cookies_2['sRefreshToken']['secure']
    assert cookies_2['sIdRefreshToken']['secure']
    assert get_unix_timestamp(
        cookies_2['sAccessToken']['expires']) - int(time()) == TEST_ACCESS_TOKEN_MAX_AGE_VALUE
    assert get_unix_timestamp(cookies_2['sRefreshToken']['expires']) - int(time()) == \
        TEST_REFRESH_TOKEN_MAX_AGE_VALUE * 60
    assert cookies_2['sIdRefreshToken']['value'] + \
        ';' == response_2.headers['Id-Refresh-Token'][:-13]
    assert int(response_2.headers['Id-Refresh-Token'][-13:-3]) == \
        get_unix_timestamp(cookies_2['sIdRefreshToken']['expires'])
    assert response_2.headers[ACCESS_CONTROL_EXPOSE_HEADER] == ACCESS_CONTROL_EXPOSE_HEADER_ANTI_CSRF_ENABLE

    request_3 = core_config_app.test_client()
    request_3.set_cookie(
        'localhost',
        'sAccessToken',
        cookies_2['sAccessToken']['value'])
    request_3.set_cookie(
        'localhost',
        'sIdRefreshToken',
        cookies_2['sIdRefreshToken']['value'])
    response_3 = request_3.get(
        '/info',
        headers={
            'anti-csrf': response_2.headers.get('anti-csrf')})
    assert response_3.status_code == 200
    cookies_3 = extract_all_cookies(response_3)
    assert cookies_3['sAccessToken']['value'] != cookies_2['sAccessToken']['value']
    assert response_3.headers.get('anti-csrf') is None
    assert cookies_3.get('sRefreshToken') is None
    assert cookies_3.get('sIdRefreshToken') is None
    assert cookies_3['sAccessToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
    assert cookies_3['sAccessToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
    assert cookies_3['sAccessToken']['httponly']
    assert cookies_3['sAccessToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
    assert cookies_3['sAccessToken']['secure']

    request_4 = core_config_app.test_client()
    request_4.set_cookie(
        'localhost',
        'sAccessToken',
        cookies_3['sAccessToken']['value'])
    request_4.set_cookie(
        'localhost',
        'sIdRefreshToken',
        cookies_2['sIdRefreshToken']['value'])
    response_4 = request_4.post(
        '/logout',
        headers={
            'anti-csrf': response_2.headers.get('anti-csrf')})
    cookies_4 = extract_all_cookies(response_4)
    assert response_4.headers.get('anti-csrf') is None
    assert cookies_4['sAccessToken']['value'] == ''
    assert cookies_4['sRefreshToken']['value'] == ''
    assert cookies_4['sIdRefreshToken']['value'] == ''
    assert cookies_4['sAccessToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
    assert cookies_4['sRefreshToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
    assert cookies_4['sIdRefreshToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
    assert cookies_4['sAccessToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
    assert cookies_4['sRefreshToken']['path'] == TEST_REFRESH_TOKEN_PATH_KEY_VALUE
    assert cookies_4['sIdRefreshToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
    assert cookies_4['sAccessToken']['httponly']
    assert cookies_4['sRefreshToken']['httponly']
    assert cookies_4['sIdRefreshToken']['httponly']
    assert cookies_4['sAccessToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
    assert cookies_4['sRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
    assert cookies_4['sIdRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
    assert cookies_4['sAccessToken']['secure']
    assert cookies_4['sRefreshToken']['secure']
    assert cookies_4['sIdRefreshToken']['secure']
    assert get_unix_timestamp(cookies_4['sAccessToken']['expires']) == 0
    assert get_unix_timestamp(cookies_4['sRefreshToken']['expires']) == 0
    assert get_unix_timestamp(cookies_4['sIdRefreshToken']['expires']) == 0
    assert response_4.headers['Id-Refresh-Token'] == 'remove'


def test_cookie_and_header_values_with_csrf_disabled(core_config_app):
    set_key_value_in_config(TEST_ENABLE_ANTI_CSRF_CONFIG_KEY, False)
    set_key_value_in_config(
        TEST_COOKIE_SAME_SITE_CONFIG_KEY,
        TEST_COOKIE_SAME_SITE_VALUE)
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_MAX_AGE_CONFIG_KEY,
        TEST_ACCESS_TOKEN_MAX_AGE_VALUE)
    set_key_value_in_config(
        TEST_ACCESS_TOKEN_PATH_CONFIG_KEY,
        TEST_ACCESS_TOKEN_PATH_VALUE)
    set_key_value_in_config(
        TEST_COOKIE_DOMAIN_CONFIG_KEY,
        TEST_COOKIE_DOMAIN_VALUE)
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_MAX_AGE_CONFIG_KEY,
        TEST_REFRESH_TOKEN_MAX_AGE_VALUE)
    set_key_value_in_config(
        TEST_REFRESH_TOKEN_PATH_CONFIG_KEY,
        TEST_REFRESH_TOKEN_PATH_KEY_VALUE)
    set_key_value_in_config(
        TEST_COOKIE_SECURE_CONFIG_KEY,
        TEST_COOKIE_SECURE_VALUE)
    start_st()

    response_1 = core_config_app.test_client().get('/login')
    cookies_1 = extract_all_cookies(response_1)

    assert response_1.headers.get('anti-csrf') is None
    assert cookies_1['sAccessToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
    assert cookies_1['sRefreshToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
    assert cookies_1['sIdRefreshToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
    assert cookies_1['sAccessToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
    assert cookies_1['sRefreshToken']['path'] == TEST_REFRESH_TOKEN_PATH_KEY_VALUE
    assert cookies_1['sIdRefreshToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
    assert cookies_1['sAccessToken']['httponly']
    assert cookies_1['sRefreshToken']['httponly']
    assert cookies_1['sIdRefreshToken']['httponly']
    assert cookies_1['sAccessToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
    assert cookies_1['sRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
    assert cookies_1['sIdRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
    assert cookies_1['sAccessToken']['secure']
    assert cookies_1['sRefreshToken']['secure']
    assert cookies_1['sIdRefreshToken']['secure']
    assert get_unix_timestamp(
        cookies_1['sAccessToken']['expires']) - int(time()) in {
            TEST_ACCESS_TOKEN_MAX_AGE_VALUE,
            TEST_ACCESS_TOKEN_MAX_AGE_VALUE - 1
    }
    assert get_unix_timestamp(cookies_1['sRefreshToken']['expires']) - int(time()) == \
        TEST_REFRESH_TOKEN_MAX_AGE_VALUE * 60
    assert cookies_1['sIdRefreshToken']['value'] + \
        ';' == response_1.headers['Id-Refresh-Token'][:-13]
    assert int(response_1.headers['Id-Refresh-Token'][-13:-3]) == \
        get_unix_timestamp(cookies_1['sIdRefreshToken']['expires'])
    assert response_1.headers[ACCESS_CONTROL_EXPOSE_HEADER] == ACCESS_CONTROL_EXPOSE_HEADER_ANTI_CSRF_DISABLE

    request_2 = core_config_app.test_client()
    request_2.set_cookie(
        'localhost',
        'sRefreshToken',
        cookies_1['sRefreshToken']['value'])
    response_2 = request_2.post('/refresh')
    cookies_2 = extract_all_cookies(response_2)
    assert cookies_1['sAccessToken']['value'] != cookies_2['sAccessToken']['value']
    assert cookies_1['sRefreshToken']['value'] != cookies_2['sRefreshToken']['value']
    assert cookies_1['sIdRefreshToken']['value'] != cookies_2['sIdRefreshToken']['value']
    assert response_2.headers.get('anti-csrf') is None
    assert cookies_2['sAccessToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
    assert cookies_2['sRefreshToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
    assert cookies_2['sIdRefreshToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
    assert cookies_2['sAccessToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
    assert cookies_2['sRefreshToken']['path'] == TEST_REFRESH_TOKEN_PATH_KEY_VALUE
    assert cookies_2['sIdRefreshToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
    assert cookies_2['sAccessToken']['httponly']
    assert cookies_2['sRefreshToken']['httponly']
    assert cookies_2['sIdRefreshToken']['httponly']
    assert cookies_2['sAccessToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
    assert cookies_2['sRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
    assert cookies_2['sIdRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
    assert cookies_2['sAccessToken']['secure']
    assert cookies_2['sRefreshToken']['secure']
    assert cookies_2['sIdRefreshToken']['secure']
    assert get_unix_timestamp(
        cookies_2['sAccessToken']['expires']) - int(time()) == TEST_ACCESS_TOKEN_MAX_AGE_VALUE
    assert get_unix_timestamp(cookies_2['sRefreshToken']['expires']) - int(time()) == \
        TEST_REFRESH_TOKEN_MAX_AGE_VALUE * 60
    assert cookies_2['sIdRefreshToken']['value'] + \
        ';' == response_2.headers['Id-Refresh-Token'][:-13]
    assert int(response_2.headers['Id-Refresh-Token'][-13:-3]) == \
        get_unix_timestamp(cookies_2['sIdRefreshToken']['expires'])
    assert response_2.headers[ACCESS_CONTROL_EXPOSE_HEADER] == ACCESS_CONTROL_EXPOSE_HEADER_ANTI_CSRF_DISABLE

    request_3 = core_config_app.test_client()
    request_3.set_cookie(
        'localhost',
        'sAccessToken',
        cookies_2['sAccessToken']['value'])
    request_3.set_cookie(
        'localhost',
        'sIdRefreshToken',
        cookies_2['sIdRefreshToken']['value'])
    response_3 = request_3.get('/info')
    assert response_3.status_code == 200
    cookies_3 = extract_all_cookies(response_3)
    assert cookies_3['sAccessToken']['value'] != cookies_2['sAccessToken']['value']
    assert response_3.headers.get('anti-csrf') is None
    assert cookies_3.get('sRefreshToken') is None
    assert cookies_3.get('sIdRefreshToken') is None
    assert cookies_3['sAccessToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
    assert cookies_3['sAccessToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
    assert cookies_3['sAccessToken']['httponly']
    assert cookies_3['sAccessToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
    assert cookies_3['sAccessToken']['secure']

    request_4 = core_config_app.test_client()
    request_4.set_cookie(
        'localhost',
        'sAccessToken',
        cookies_3['sAccessToken']['value'])
    request_4.set_cookie(
        'localhost',
        'sIdRefreshToken',
        cookies_2['sIdRefreshToken']['value'])
    response_4 = request_4.post(
        '/logout',
        headers={
            'anti-csrf': response_2.headers.get('anti-csrf')})
    cookies_4 = extract_all_cookies(response_4)
    assert response_4.headers.get('anti-csrf') is None
    assert cookies_4['sAccessToken']['value'] == ''
    assert cookies_4['sRefreshToken']['value'] == ''
    assert cookies_4['sIdRefreshToken']['value'] == ''
    assert cookies_4['sAccessToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
    assert cookies_4['sRefreshToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
    assert cookies_4['sIdRefreshToken']['domain'] == TEST_COOKIE_DOMAIN_VALUE
    assert cookies_4['sAccessToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
    assert cookies_4['sRefreshToken']['path'] == TEST_REFRESH_TOKEN_PATH_KEY_VALUE
    assert cookies_4['sIdRefreshToken']['path'] == TEST_ACCESS_TOKEN_PATH_VALUE
    assert cookies_4['sAccessToken']['httponly']
    assert cookies_4['sRefreshToken']['httponly']
    assert cookies_4['sIdRefreshToken']['httponly']
    assert cookies_4['sAccessToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
    assert cookies_4['sRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
    assert cookies_4['sIdRefreshToken']['samesite'] == TEST_COOKIE_SAME_SITE_VALUE
    assert cookies_4['sAccessToken']['secure']
    assert cookies_4['sRefreshToken']['secure']
    assert cookies_4['sIdRefreshToken']['secure']
    assert get_unix_timestamp(cookies_4['sAccessToken']['expires']) == 0
    assert get_unix_timestamp(cookies_4['sRefreshToken']['expires']) == 0
    assert get_unix_timestamp(cookies_4['sIdRefreshToken']['expires']) == 0
    assert response_4.headers['Id-Refresh-Token'] == 'remove'


def test_supertokens_token_theft_detection(app):
    start_st()
    response_1 = app.test_client().get('/login')
    cookies_1 = extract_all_cookies(response_1)
    request_2 = app.test_client()
    request_2.set_cookie(
        'localhost',
        'sRefreshToken',
        cookies_1['sRefreshToken']['value'])
    response_2 = request_2.post('/refresh')
    cookies_2 = extract_all_cookies(response_2)
    request_3 = app.test_client()
    request_3.set_cookie(
        'localhost',
        'sAccessToken',
        cookies_2['sAccessToken']['value'])
    request_3.set_cookie(
        'localhost',
        'sIdRefreshToken',
        cookies_2['sIdRefreshToken']['value'])
    request_3.get(
        '/info',
        headers={
            'anti-csrf': response_2.headers.get('anti-csrf')})
    request_4 = app.test_client()
    request_4.set_cookie(
        'localhost',
        'sRefreshToken',
        cookies_1['sRefreshToken']['value'])
    response_4 = request_4.post('/refresh')
    assert response_4.json == {'error': 'token theft detected'}
    assert response_4.status_code == 440


def test_supertokens_basic_usage_of_sessions(app):
    start_st()
    response_1 = app.test_client().get('/login')
    cookies_1 = extract_all_cookies(response_1)

    request_2 = app.test_client()
    request_2.set_cookie(
        'localhost',
        'sAccessToken',
        cookies_1['sAccessToken']['value'])
    request_2.set_cookie(
        'localhost',
        'sIdRefreshToken',
        cookies_1['sIdRefreshToken']['value'])
    request_2.get(
        '/info',
        headers={
            'anti-csrf': response_1.headers.get('anti-csrf')})
    assert not ProcessState.get_service_called()

    request_3 = app.test_client()
    request_3.set_cookie(
        'localhost',
        'sRefreshToken',
        cookies_1['sRefreshToken']['value'])
    response_3 = request_3.post('/refresh')
    cookies_3 = extract_all_cookies(response_3)

    request_4 = app.test_client()
    request_4.set_cookie(
        'localhost',
        'sAccessToken',
        cookies_3['sAccessToken']['value'])
    request_4.set_cookie(
        'localhost',
        'sIdRefreshToken',
        cookies_3['sIdRefreshToken']['value'])
    response_4 = request_4.get(
        '/info',
        headers={
            'anti-csrf': response_3.headers.get('anti-csrf')})
    cookies_4 = extract_all_cookies(response_4)
    assert ProcessState.get_service_called()

    request_5 = app.test_client()
    request_5.set_cookie(
        'localhost',
        'sAccessToken',
        cookies_4['sAccessToken']['value'])
    request_5.set_cookie(
        'localhost',
        'sIdRefreshToken',
        cookies_3['sIdRefreshToken']['value'])
    response_5 = request_5.get(
        '/handle',
        headers={
            'anti-csrf': response_3.headers.get('anti-csrf')})
    assert not ProcessState.get_service_called()

    assert revoke_session(response_5.json['s'])


def test_supertokens_session_verify_with_anti_csrf(app):
    start_st()
    response_1 = app.test_client().get('/login')
    cookies_1 = extract_all_cookies(response_1)

    request_2 = app.test_client()
    request_2.set_cookie(
        'localhost',
        'sAccessToken',
        cookies_1['sAccessToken']['value'])
    request_2.set_cookie(
        'localhost',
        'sIdRefreshToken',
        cookies_1['sIdRefreshToken']['value'])
    response_2 = request_2.get(
        '/info',
        headers={
            'anti-csrf': response_1.headers.get('anti-csrf')})
    assert response_2.status_code == 200

    request_3 = app.test_client()
    request_3.set_cookie(
        'localhost',
        'sAccessToken',
        cookies_1['sAccessToken']['value'])
    request_3.set_cookie(
        'localhost',
        'sIdRefreshToken',
        cookies_1['sIdRefreshToken']['value'])
    response_3 = request_3.get(
        '/handle',
        headers={
            'anti-csrf': response_1.headers.get('anti-csrf')})
    assert response_3.status_code == 200


def test_supertokens_session_verify_without_anti_csrf(app):
    start_st()
    response_1 = app.test_client().get('/login')
    cookies_1 = extract_all_cookies(response_1)

    request_2 = app.test_client()
    request_2.set_cookie(
        'localhost',
        'sAccessToken',
        cookies_1['sAccessToken']['value'])
    request_2.set_cookie(
        'localhost',
        'sIdRefreshToken',
        cookies_1['sIdRefreshToken']['value'])
    response_2 = request_2.get('/info')
    assert response_2.status_code == 401
    assert response_2.json == {'error_msg': 'try refresh token'}

    request_3 = app.test_client()
    request_3.set_cookie(
        'localhost',
        'sAccessToken',
        cookies_1['sAccessToken']['value'])
    request_3.set_cookie(
        'localhost',
        'sIdRefreshToken',
        cookies_1['sIdRefreshToken']['value'])
    response_3 = request_3.get('/handle')
    assert response_3.status_code == 200


def test_supertokens_revoking_of_sessions(app):
    start_st()
    revoke_all_sessions_for_user('userId')
    assert len(get_all_session_handles_for_user('userId')) == 0
    session = create_new_session(Response(''), 'userId', {}, {})
    assert len(get_all_session_handles_for_user('userId')) == 1
    assert revoke_session(session.get_handle())
    assert len(get_all_session_handles_for_user('userId')) == 0
    create_new_session(Response(''), 'userId', {}, {})
    create_new_session(Response(''), 'userId', {}, {})
    assert len(get_all_session_handles_for_user('userId')) == 2
    assert len(revoke_all_sessions_for_user('userId')) == 2
    assert len(get_all_session_handles_for_user('userId')) == 0
    assert not revoke_session('random')
    assert len(revoke_all_sessions_for_user('randomUserId')) == 0


def test_supertokens_manipulating_session_data(app):
    start_st()
    session = create_new_session(Response(''), 'userId', {}, {})
    session_data_1 = get_session_data(session.get_handle())
    assert session_data_1 == {}
    update_session_data(session.get_handle(), {'key': 'value'})
    session_data_2 = session.get_session_data()
    assert session_data_2 == {'key': 'value'}
    session.update_session_data({'key': 'new_value'})
    session_data_3 = get_session_data(session.get_handle())
    assert session_data_3 == {'key': 'new_value'}
    try:
        update_session_data('incorrect', {'key': 'value'})
        assert False
    except SuperTokensUnauthorisedError:
        assert True


def test_supertokens_manipulating_jwt_data(app):
    start_st()
    session_1 = create_new_session(Response(''), 'userId', {}, {})
    session_2 = create_new_session(Response(''), 'userId', {}, {})
    session_data_1_1 = get_jwt_payload(session_1.get_handle())
    assert session_data_1_1 == {}
    session_data_2_1 = get_jwt_payload(session_2.get_handle())
    assert session_data_2_1 == {}

    update_jwt_payload(session_1.get_handle(), {'key': 'value'})
    session_data_1_2 = get_jwt_payload(session_1.get_handle())
    assert session_data_1_2 == {'key': 'value'}
    session_data_2_2 = get_jwt_payload(session_2.get_handle())
    assert session_data_2_2 == {}

    try:
        update_jwt_payload('incorrect', {'key': 'value'})
        assert False
    except SuperTokensUnauthorisedError:
        assert True


def test_supertokens_anti_csrf_disabled_for_core(app):
    set_key_value_in_config(TEST_ENABLE_ANTI_CSRF_CONFIG_KEY, False)
    start_st()
    response_1 = app.test_client().get('/login')
    cookies_1 = extract_all_cookies(response_1)

    request_2 = app.test_client()
    request_2.set_cookie(
        'localhost',
        'sAccessToken',
        cookies_1['sAccessToken']['value'])
    request_2.set_cookie(
        'localhost',
        'sIdRefreshToken',
        cookies_1['sIdRefreshToken']['value'])
    response_2 = request_2.get('/info')
    assert response_2.status_code == 200

    request_3 = app.test_client()
    request_3.set_cookie(
        'localhost',
        'sAccessToken',
        cookies_1['sAccessToken']['value'])
    request_3.set_cookie(
        'localhost',
        'sIdRefreshToken',
        cookies_1['sIdRefreshToken']['value'])
    response_3 = request_3.get('/handle')
    assert response_3.status_code == 200


def test_supertokens_set_options_headers_api(app):
    response = Response('')
    set_relevant_headers_for_options_api(response)
    assert response.headers.get(
        'Access-Control-Allow-Headers') == 'anti-csrf, supertokens-sdk-name, supertokens-sdk-version'
    assert response.headers.get('Access-Control-Allow-Credentials') == 'true'
