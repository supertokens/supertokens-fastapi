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

from json import dumps
import sys
sys.path.append('../..')  # noqa: E402
from supertokens_fastapi import (
    SuperTokens, Session, create_new_session,
    handshake_info, supertokens_session,
    supertokens_session_with_anti_csrf,
    revoke_all_sessions_for_user,
    get_cors_allowed_headers
)
from fastapi import FastAPI, Depends
from fastapi.requests import Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse

index_file = open("./templates/index.html", "r")
file_contents = index_file.read()
index_file.close()

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8080"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["Content-Type"] + get_cors_allowed_headers(),
)

supertokens = SuperTokens(app, hosts='http://127.0.0.1:9000')


def try_refresh_token(_):
    return JSONResponse(content={'error': 'try refresh token'}, status_code=401)


def unauthorised(_):
    return JSONResponse(content={'error': 'unauthorised'}, status_code=401)


supertokens.set_try_refresh_token_error_handler(try_refresh_token)
supertokens.set_unauthorised_error_handler(unauthorised)


class Test:
    no_of_times_refresh_called_during_test = 0
    no_of_times_get_session_called_during_test = 0

    @staticmethod
    def reset():
        handshake_info.HandshakeInfo.reset()
        Test.no_of_times_refresh_called_during_test = 0
        Test.no_of_times_get_session_called_during_test = 0

    @staticmethod
    def increment_refresh():
        Test.no_of_times_refresh_called_during_test += 1

    @staticmethod
    def increment_get_session():
        Test.no_of_times_get_session_called_during_test += 1

    @staticmethod
    def get_session_called_count():
        return Test.no_of_times_get_session_called_during_test

    @staticmethod
    def get_refresh_called_count():
        return Test.no_of_times_refresh_called_during_test


@app.get('/index.html')
def send_file():
    return HTMLResponse(content=file_contents)


def send_options_api_response():
    response = PlainTextResponse(content='', status_code=200)
    return response


@app.options("/login")
def login_options():
    return send_options_api_response()


@app.post('/login')
async def login(request: Request):
    user_id = (await request.json())['userId']
    await create_new_session(request, user_id)
    return PlainTextResponse(content=user_id)


@app.options("/beforeeach")
def before_each_options():
    return send_options_api_response()


@app.post('/beforeeach')
def before_each():
    Test.reset()
    return PlainTextResponse('')


@app.options("/testUserConfig")
def test_user_config_options():
    return send_options_api_response()


@app.post('/testUserConfig')
def test_config():
    return PlainTextResponse('')


@app.options("/multipleInterceptors")
def multiple_interceptors_options():
    return send_options_api_response()


@app.post('/multipleInterceptors')
def multiple_interceptors(request: Request):
    result_bool = 'success' if 'interceptorheader2' in request.headers \
                               and 'interceptorheader1' in request.headers else 'failure'
    return PlainTextResponse(result_bool)


@app.options("/")
def options():
    return send_options_api_response()


@app.get('/')
def get_info(session: Session = Depends(supertokens_session_with_anti_csrf)):
    Test.increment_get_session()
    return PlainTextResponse(content=session.get_user_id(), headers={
        'Cache-Control': 'no-cache, private'
    })


@app.options("/update-jwt")
def update_options():
    return send_options_api_response()


@app.get('/update-jwt')
def update_jwt(session: Session = Depends(supertokens_session_with_anti_csrf)):
    Test.increment_get_session()
    return JSONResponse(content=session.get_jwt_payload(), headers={
        'Cache-Control': 'no-cache, private'
    })


@app.post('/update-jwt')
async def update_jwt_post(request: Request, session: Session = Depends(supertokens_session_with_anti_csrf)):
    await session.update_jwt_payload(await request.json())
    Test.increment_get_session()
    return JSONResponse(content=session.get_jwt_payload(), headers={
        'Cache-Control': 'no-cache, private'
    })


@app.options("/testing")
def testing_options():
    return send_options_api_response()


@app.get('/testing')
def testing(request: Request):
    if 'testing' in request.headers:
        return PlainTextResponse(content='success', headers={'testing': request.headers['testing']})
    return PlainTextResponse(content='success')


@app.put('/testing')
def testing_put(request: Request):
    if 'testing' in request.headers:
        return PlainTextResponse(content='success', headers={'testing': request.headers['testing']})
    return PlainTextResponse(content='success')


@app.post('/testing')
def testing_post(request: Request):
    if 'testing' in request.headers:
        return PlainTextResponse(content='success', headers={'testing': request.headers['testing']})
    return PlainTextResponse(content='success')


@app.delete('/testing')
def testing_delete(request: Request):
    if 'testing' in request.headers:
        return PlainTextResponse(content='success', headers={'testing': request.headers['testing']})
    return PlainTextResponse(content='success')


@app.options("/logout")
def logout_options():
    return send_options_api_response()


@app.post('/logout')
async def logout(session: Session = Depends(supertokens_session)):
    await session.revoke_session()
    return PlainTextResponse(content='success')


@app.options("/revokeAll")
def revoke_all_options():
    return send_options_api_response()


@app.post('/revokeAll')
async def revoke_all(session: Session = Depends(supertokens_session_with_anti_csrf)):
    await revoke_all_sessions_for_user(session.get_user_id())
    return PlainTextResponse(content='success')


@app.options("/refresh")
def refresh_options():
    return send_options_api_response()


@app.post('/refresh')
def refresh(_: Session = Depends(supertokens_session)):
    Test.increment_refresh()
    return PlainTextResponse(content='refresh success')


@app.options("/refreshCalledTime")
def refresh_called_time_options():
    return send_options_api_response()


@app.get('/refreshCalledTime')
def get_refresh_called_info():
    return PlainTextResponse(content=dumps(Test.get_refresh_called_count()))


@app.options("/getSessionCalledTime")
def get_session_called_time_options():
    return send_options_api_response()


@app.get('/getSessionCalledTime')
def get_session_called_info():
    return PlainTextResponse(content=dumps(Test.get_session_called_count()))


@app.options("/ping")
def ping_options():
    return send_options_api_response()


@app.get('/ping')
def ping():
    return PlainTextResponse(content='success')


@app.options("/testHeader")
def test_header_options():
    return send_options_api_response()


@app.get('/testHeader')
def test_header(request: Request):
    success_info = request.headers.get('st-custom-header')
    return JSONResponse({'success': success_info})


@app.options("/checkDeviceInfo")
def check_device_info_options():
    return send_options_api_response()


@app.get('/checkDeviceInfo')
def check_device_info(request: Request):
    sdk_name = request.headers.get('supertokens-sdk-name')
    sdk_version = request.headers.get('supertokens-sdk-version')
    return PlainTextResponse('true' if sdk_name == 'website' and isinstance(sdk_version, str) else 'false')


@app.options("/checkAllowCredentials")
def check_allow_credentials_options():
    return send_options_api_response()


@app.get('/checkAllowCredentials')
def check_allow_credentials(request: Request):
    return PlainTextResponse(dumps('allow-credentials' in request.headers), 200)


@app.route('/testError', methods=['GET', 'OPTIONS'])
def test_error(request: Request):
    if request.method == 'OPTIONS':
        return send_options_api_response()
    return PlainTextResponse('test error message', 500)


@app.exception_handler(405)
def f_405(_, e):
    return PlainTextResponse('', status_code=404)
