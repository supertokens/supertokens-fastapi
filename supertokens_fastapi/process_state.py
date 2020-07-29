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

from os import environ
from supertokens_fastapi.exceptions import raise_general_exception


class ProcessState:
    __instance = None

    def __init__(self):
        self.service_called = False

    @staticmethod
    def __get_instance():
        if ProcessState.__instance is None:
            ProcessState.__instance = ProcessState()
        return ProcessState.__instance

    @staticmethod
    def update_service_called(b):
        instance = ProcessState.__get_instance()
        instance.service_called = b

    @staticmethod
    def get_service_called():
        return ProcessState.__get_instance().service_called

    @staticmethod
    def reset():
        if ('SUPERTOKENS_ENV' not in environ) or (
                environ['SUPERTOKENS_ENV'] != 'testing'):
            raise_general_exception(
                'calling testing function in non testing env')
        ProcessState.__instance = None
