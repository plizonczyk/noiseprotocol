import glob
import json
import os

import pytest

VECTORS = glob.glob(os.path.join(os.path.dirname(__file__), 'vectors/*.json'))


@pytest.fixture(params=VECTORS)
def vector(request):
    with open(request.param) as f:
        yield json.load(f)


def test_vector(vector):
    assert False
