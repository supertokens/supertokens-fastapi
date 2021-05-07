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

import sys

sys.path.append('../..')  # noqa: E402
from supertokens_fastapi import init, get_all_cors_headers, session, emailpassword, middleware
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse
from starlette.exceptions import ExceptionMiddleware

index_file = open("./templates/index.html", "r")
file_contents = index_file.read()
index_file.close()

app = FastAPI()

init(app, {
    'supertokens': {
        'connection_uri': "https://try.supertokens.io",
    },
    'app_info': {
        'app_name': "SuperTokens Demo",
        'api_domain': "http://localhost:9000",
        'website_domain': "http://localhost:8888",
        'api_base_path': "/auth"
    },
    'recipe_list': [emailpassword.init(), session.init()]
})

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8888"
    ],
    allow_credentials=True,
    allow_methods=["GET", "PUT", "POST", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Content-Type"] + get_all_cors_headers(),
)

app.add_middleware(middleware())
app.add_middleware(ExceptionMiddleware, handlers=app.exception_handlers)


@app.get('/index.html')
def send_file():
    return HTMLResponse(content=file_contents)


@app.get('/user')
async def get_user(user_session=Depends(session.verify_session())):
    print(user_session.get_user_id())
    return JSONResponse({})


@app.exception_handler(405)
def f_405(_, e):
    return PlainTextResponse('', status_code=404)


@app.exception_handler(Exception)
def f_500(_, e):
    return JSONResponse(status_code=500, content={})
