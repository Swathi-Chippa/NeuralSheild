import sys
from pathlib import Path
from unittest.mock import patch

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import app


PHISHING_FEATURES = [-1] * 28
LEGITIMATE_FEATURES = [1] * 28


def test_health():
    response = app.test_client().get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_predict_classifies_phishing_features():
    with patch("app.extract_features", return_value=PHISHING_FEATURES):
        response = app.test_client().post("/predict", json={"url": "https://example.com"})
    assert response.status_code == 200
    assert response.get_json() == {"prediction": "Phishing Website"}


def test_predict_classifies_legitimate_features():
    with patch("app.extract_features", return_value=LEGITIMATE_FEATURES):
        response = app.test_client().post("/predict", json={"url": "https://example.com"})
    assert response.status_code == 200
    assert response.get_json() == {"prediction": "Legitimate Website"}


# 0.35 is between the old 0.5 default and the chosen 0.3 threshold, so this
# guards against regressing to 0.5 while the extreme-vector tests still pass.
def test_predict_uses_0_3_threshold_not_0_5():
    with (
        patch("app.extract_features", return_value=[0] * 28),
        patch("app.model.classes_", new=np.array([-1, 1])),
        patch("app.model.predict_proba", return_value=np.array([[0.35, 0.65]])),
    ):
        response = app.test_client().post("/predict", json={"url": "https://example.com"})

    assert response.status_code == 200
    assert response.get_json() == {"prediction": "Phishing Website"}


def test_predict_rejects_missing_json():
    response = app.test_client().post("/predict")
    assert response.status_code == 400
    assert response.get_json() == {"error": "Request body must be valid JSON"}


def test_predict_rejects_missing_url():
    response = app.test_client().post("/predict", json={})
    assert response.status_code == 400
    assert response.get_json() == {"error": "Missing required field: url"}


def test_predict_rejects_empty_url():
    response = app.test_client().post("/predict", json={"url": ""})
    assert response.status_code == 400
    assert response.get_json() == {"error": "url must be a non-empty string"}


def test_predict_rejects_non_absolute_url():
    response = app.test_client().post("/predict", json={"url": "not-a-url"})
    assert response.status_code == 400
    assert response.get_json() == {
        "error": "url must be an absolute http:// or https:// URL"
    }


def test_predict_hides_feature_extraction_exception():
    with patch("app.extract_features", side_effect=RuntimeError("secret failure")):
        response = app.test_client().post("/predict", json={"url": "https://example.com"})
    assert response.status_code == 500
    assert response.get_json() == {"error": "Failed to analyze URL"}
    assert b"secret failure" not in response.data
