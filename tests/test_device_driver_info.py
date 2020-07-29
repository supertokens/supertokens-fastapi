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

from flask import Flask, make_response, jsonify
from pytest import fixture

from supertokens_fastapi import SuperTokens, create_new_session, supertokens_middleware
from supertokens_fastapi.device_info import DeviceInfo
from .utils import (
    reset, setup_st, clean_st, start_st, extract_all_cookies
)
from supertokens_fastapi.querier import Querier
from supertokens_fastapi.constants import SESSION, HELLO, VERSION, COOKIE_DOMAIN_CONFIG


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
    SuperTokens(app)

    @app.route('/login')
    def login():
        user_id = 'userId'
        response = make_response(jsonify({'userId': user_id}), 200)
        create_new_session(response, user_id, {}, {})
        return response

    @app.route('/info')
    @supertokens_middleware()
    def info():
        return {}

    return app


def test_driver_info_check_without_frontend_sdk():
    start_st()
    response = Querier.get_instance().send_post_request(
        SESSION, {'userId': 'abc'}, True)
    assert response['userId'] == 'abc'
    assert 'deviceDriverInfo' in response
    assert response['deviceDriverInfo'] == {
        'driver': {
            'name': 'flask',
            'version': VERSION},
        'frontendSDK': []}
    response = Querier.get_instance().send_post_request(
        HELLO, {'userId': 'pqr'}, True)
    assert response['userId'] == 'pqr'
    assert 'deviceDriverInfo' not in response


def test_driver_info_check_with_frontend_sdk(app):
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
            'supertokens-sdk-name': 'ios',
            'supertokens-sdk-version': '0.0.0'})
    request_3 = app.test_client()
    request_3.set_cookie(
        'localhost',
        'sAccessToken',
        cookies_1['sAccessToken']['value'])
    request_3.set_cookie(
        'localhost',
        'sIdRefreshToken',
        cookies_1['sIdRefreshToken']['value'])
    request_3.get(
        '/info',
        headers={
            'supertokens-sdk-name': 'android',
            'supertokens-sdk-version': VERSION})

    assert DeviceInfo.get_instance().get_frontend_sdk() == [{'name': 'ios', 'version': '0.0.0'},
                                                            {'name': 'android', 'version': VERSION}]
