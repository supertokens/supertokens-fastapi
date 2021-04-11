help:
	@echo "  \x1b[33;1mcheck-lint: \x1b[0mtest styling of code for the library using flak8"
	@echo "        \x1b[33;1mtest: \x1b[0mruns pytest"
	@echo "        \x1b[33;1mlint: \x1b[0mformat code using autopep8"
	@echo "\x1b[33;1mset-up-hooks: \x1b[0mset up various git hooks"
	@echo " \x1b[33;1mdev-install: \x1b[0minstall all packages required for development"
	@echo "        \x1b[33;1mhelp: \x1b[0mprints this"

lint:
	autopep8 -r -i -a supertokens_fastapi tests

check-lint:
	flake8 supertokens_fastapi tests

set-up-hooks:
	cp hooks/pre-commit.sh .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit

test:
	pytest

dev-install:
	pip3 install -e .[dev]