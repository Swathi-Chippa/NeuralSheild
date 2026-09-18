import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from feature_extraction import SSRFBlockedError, extract_features, resolve_and_validate_host


pytestmark = pytest.mark.integration


@pytest.mark.parametrize("hostname", ["169.254.169.254", "localhost"])
def test_resolve_and_validate_host_blocks_private_targets(hostname):
    with pytest.raises(SSRFBlockedError):
        resolve_and_validate_host(hostname)


def test_google_regression_features():
    features = extract_features("https://www.google.com")
    assert features[7] == 1
    assert features[25] == 1
