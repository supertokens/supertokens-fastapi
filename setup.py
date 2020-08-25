from setuptools import setup, find_packages
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, "README.md"), mode="r", encoding="utf-8") as f:
    long_description = f.read()

extras_require = {
    'dev': ([
        'pytest',
        'jsonschema',
        'flake8',
        'autopep8',
        'PyYAML',
        'uvicorn',
        'requests',
        'pytest-asyncio',
        'respx',
        'nest-asyncio'
    ])
}

setup(
    name="supertokens_fastapi",
    version="1.0.0",
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
        "PyJWT",
        "fastapi",
        "starlette",
        "httpx",
        "pycryptodome",
    ],
    python_requires='>=3.7',
    extras_require=extras_require
)
