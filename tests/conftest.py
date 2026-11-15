import copy
import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def tenant_a():
    return load_fixture("collected_tenant_a.json")


@pytest.fixture
def tenant_a_later():
    return load_fixture("collected_tenant_a_later.json")


@pytest.fixture
def tenant_b():
    return load_fixture("collected_tenant_b_no_p1.json")


@pytest.fixture
def clone():
    return copy.deepcopy
