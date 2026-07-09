import pytest


@pytest.fixture(scope="module", autouse=True)
def do_something():
    pass
