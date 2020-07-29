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

from supertokens_fastapi.cookie_and_header import (
    set_cookie
)
from flask import request, Flask, jsonify
from supertokens_fastapi.utils import get_timestamp_ms
from pytest import fixture
from .utils import get_cookie_from_response, get_unix_timestamp, reset, clean_st, setup_st, start_st

""" @fixtures
scope: function
Run once per test function

scope: class
Run once per test class, regardless of how many test methods are in the
"""


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

    @app.route('/')
    def cookie_request():
        response = jsonify({})
        key = 'test'
        value = 'value'
        domain = 'localhost.org'
        secure = True
        http_only = False
        path = '/'
        expires = int(request.args['expiry'])
        same_site = 'none'
        set_cookie(
            response,
            key,
            value,
            expires,
            path,
            domain,
            secure,
            http_only,
            same_site)
        return response

    return app


def test_set_cookie(app):
    start_st()
    expiry = get_timestamp_ms()
    response = app.test_client().get('/?expiry=' + str(expiry))
    test_cookie = get_cookie_from_response(response, 'test')
    assert test_cookie is not None
    assert test_cookie['name'] == 'test'
    assert test_cookie['value'] == 'value'
    assert test_cookie['domain'] == 'localhost.org'
    assert test_cookie['path'] == '/'
    assert test_cookie['samesite'] == 'None'
    assert test_cookie['secure']
    assert test_cookie.get('httponly') is None
    assert get_unix_timestamp(test_cookie['expires']) == expiry // 1000
