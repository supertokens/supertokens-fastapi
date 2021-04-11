from setuptools import setup, find_packages
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, "README.md"), mode="r", encoding="utf-8") as f:
    long_description = f.read()

extras_require = {
    'dev': ([
        'pytest==6.2.3',
        'jsonschema==3.2.0',
        'flake8==3.9.0',
        'autopep8==1.5.6',
        'PyYAML==5.4.1',
        'uvicorn==0.13.4',
        'requests==2.25.1',
        'pytest-asyncio==0.14.0',
        'respx==0.16.3',
        'nest-asyncio==1.5.1'
    ])
}

setup(
    name="supertokens_fastapi",
    version="1.1.1",
    author="SuperTokens",
    license="Apache 2.0",
    author_email="team@supertokens.io",
    description="SuperTokens session management solution for fastapi",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/supertokens/supertokens-fastapi",
    packages=find_packages(exclude=["tests", ]),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Intended Audience :: Developers",
        "Topic :: Internet :: WWW/HTTP :: Session",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords="",
    install_requires=[
        "PyJWT==2.0.*",
        "fastapi>=0.60",
        "starlette==0.13.*",
        "httpx==0.15.*",
        "pycryptodome==3.10.*",
    ],
    python_requires='>=3.7',
    extras_require=extras_require
)
