import pytest

from tests.vuln_app import make_vuln_app
from tests.poll_app import make_poll_server


@pytest.fixture(scope="session")
def vuln_base_url():
    server = make_vuln_app()
    host, port = server.server_address
    yield f"http://{host}:{port}"
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="session")
def poll_base_url():
    server = make_poll_server()
    host, port = server.server_address
    yield f"http://{host}:{port}"
    server.shutdown()
    server.server_close()
