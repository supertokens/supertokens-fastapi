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

from supertokens_fastapi.querier import Querier
from supertokens_fastapi.utils import find_max_version
from supertokens_fastapi.exceptions import SuperTokensGeneralError
from .utils import (
    reset, setup_st, clean_st, start_st,
    API_VERSION_TEST_BASIC_RESULT,
    API_VERSION_TEST_NON_SUPPORTED_SV,
    API_VERSION_TEST_NON_SUPPORTED_CV,
    API_VERSION_TEST_SINGLE_SUPPORTED_SV,
    API_VERSION_TEST_SINGLE_SUPPORTED_CV,
    API_VERSION_TEST_MULTIPLE_SUPPORTED_SV,
    API_VERSION_TEST_MULTIPLE_SUPPORTED_CV,
    API_VERSION_TEST_SINGLE_SUPPORTED_RESULT,
    API_VERSION_TEST_MULTIPLE_SUPPORTED_RESULT,
    SUPPORTED_CORE_DRIVER_INTERFACE_FILE
)
from json import load
from supertokens_fastapi.constants import (
    HELLO,
    SUPPORTED_CDI_VERSIONS
)


def setup_function(f):
    reset()
    clean_st()
    setup_st()


def teardown_function(f):
    reset()
    clean_st()


def test_get_api_version():
    try:
        Querier.get_instance().get_api_version()
        assert False
    except SuperTokensGeneralError:
        assert True
    start_st()
    assert Querier.get_instance().get_api_version() == API_VERSION_TEST_BASIC_RESULT
    cv = API_VERSION_TEST_SINGLE_SUPPORTED_CV
    sv = API_VERSION_TEST_SINGLE_SUPPORTED_SV
    assert find_max_version(cv, sv) == API_VERSION_TEST_SINGLE_SUPPORTED_RESULT
    cv = API_VERSION_TEST_MULTIPLE_SUPPORTED_CV
    sv = API_VERSION_TEST_MULTIPLE_SUPPORTED_SV
    assert find_max_version(
        cv, sv) == API_VERSION_TEST_MULTIPLE_SUPPORTED_RESULT
    cv = API_VERSION_TEST_NON_SUPPORTED_CV
    sv = API_VERSION_TEST_NON_SUPPORTED_SV
    assert find_max_version(cv, sv) is None


def test_check_supported_core_driver_interface_versions():
    f = open(SUPPORTED_CORE_DRIVER_INTERFACE_FILE, 'r')
    sv = set(load(f)['versions'])
    f.close()
    assert sv == set(SUPPORTED_CDI_VERSIONS)


def test_core_not_available():
    try:
        querier = Querier.get_instance()
        querier.send_get_request('/', [])
        assert False
    except SuperTokensGeneralError:
        assert True


def test_three_cores_and_round_robin():
    start_st()
    start_st('localhost', 3568)
    start_st('localhost', 3569)
    Querier.init_instance('http://localhost:3567;http://localhost:3568/;http://localhost:3569')
    querier = Querier.get_instance()
    assert querier.send_get_request(HELLO, []) == 'Hello\n'
    assert querier.send_get_request(HELLO, []) == 'Hello\n'
    assert querier.send_get_request(HELLO, []) == 'Hello\n'
    assert len(querier.get_hosts_alive_for_testing()) == 3
    assert querier.send_delete_request(HELLO, []) == 'Hello\n'
    assert len(querier.get_hosts_alive_for_testing()) == 3
    assert 'http://localhost:3567' in querier.get_hosts_alive_for_testing()
    assert 'http://localhost:3568' in querier.get_hosts_alive_for_testing()
    assert 'http://localhost:3569' in querier.get_hosts_alive_for_testing()


def test_three_cores_one_dead_and_round_robin():
    start_st()
    start_st('localhost', 3568)
    Querier.init_instance('http://localhost:3567;http://localhost:3568/;http://localhost:3569')
    querier = Querier.get_instance()
    assert querier.send_get_request(HELLO, []) == 'Hello\n'
    assert querier.send_get_request(HELLO, []) == 'Hello\n'
    assert len(querier.get_hosts_alive_for_testing()) == 2
    assert querier.send_delete_request(HELLO, []) == 'Hello\n'
    assert len(querier.get_hosts_alive_for_testing()) == 2
    assert 'http://localhost:3567' in querier.get_hosts_alive_for_testing()
    assert 'http://localhost:3568' in querier.get_hosts_alive_for_testing()
    assert 'http://localhost:3569' not in querier.get_hosts_alive_for_testing()
