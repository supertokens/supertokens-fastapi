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

from supertokens_fastapi.exceptions import raise_general_exception
from os import environ
from threading import Lock


class DeviceInfo:
    __instance = None
    __lock = Lock()

    def __init__(self):
        self.__frontend_sdk = []

    @staticmethod
    def get_instance():
        if DeviceInfo.__instance is None:
            with DeviceInfo.__lock:
                if DeviceInfo.__instance is None:
                    DeviceInfo.__instance = DeviceInfo()
        return DeviceInfo.__instance

    @staticmethod
    def reset():
        if ('SUPERTOKENS_ENV' not in environ) or (
                environ['SUPERTOKENS_ENV'] != 'testing'):
            raise_general_exception(
                'calling testing function in non testing env')
        DeviceInfo.__instance = None

    def get_frontend_sdk(self):
        return self.__frontend_sdk

    def add_to_frontend_sdk(self, sdk):
        with DeviceInfo.__lock:
            exists = False
            for i in self.__frontend_sdk:
                if i['name'] == sdk['name'] and i['version'] == sdk['version']:
                    exists = True
                    break

            if not exists:
                self.__frontend_sdk.append(sdk)
