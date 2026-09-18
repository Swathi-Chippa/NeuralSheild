import logging
import os
import pickle
import sys
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
from flask import Flask, jsonify, request
from flask_cors import CORS

from feature_extraction import extract_features

logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
PHISHING_THRESHOLD = 0.3
# Chosen via precision/recall analysis in threshold_analysis.py: default 0.5
# missed 35/980 phishing sites; 0.3 reduces that to 20/980 while raising false
# positives from 19 to 41 legitimate sites.

app = Flask(__name__)
# Update these origins if the frontend is deployed elsewhere.
CORS(app, origins=["http://localhost:5173", "http://127.0.0.1:5173"])

with (BASE_DIR / "model" / "phishing_model.pkl").open("rb") as model_file:
    model = pickle.load(model_file)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True)
    if not request.is_json or data is None:
        logger.warning("Rejected /predict request with invalid JSON")
        return jsonify({"error": "Request body must be valid JSON"}), 400
    if not isinstance(data, dict) or "url" not in data:
        logger.warning("Rejected /predict request without a url field")
        return jsonify({"error": "Missing required field: url"}), 400

    url = data["url"]
    if not isinstance(url, str) or not url.strip():
        logger.warning("Rejected /predict request with an empty or invalid url")
        return jsonify({"error": "url must be a non-empty string"}), 400

    try:
        parsed_url = urlparse(url)
    except ValueError:
        logger.warning("Rejected /predict request with a malformed URL")
        return jsonify({"error": "url must be an absolute http:// or https:// URL"}), 400
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        logger.warning("Rejected /predict request with a non-absolute URL")
        return jsonify({"error": "url must be an absolute http:// or https:// URL"}), 400

    try:
        features = extract_features(url)
        features = np.array(features).reshape(1, -1)
        probabilities = model.predict_proba(features)[0]
        phishing_class_index = list(model.classes_).index(-1)
        phishing_probability = probabilities[phishing_class_index]
        result = (
            "Phishing Website"
            if phishing_probability >= PHISHING_THRESHOLD
            else "Legitimate Website"
        )
    except Exception:
        logger.error("Failed to analyze URL", exc_info=True)
        return jsonify({"error": "Failed to analyze URL"}), 500

    return jsonify({"prediction": result})


if __name__ == "__main__":
    # debug=True must never be used outside local development because it exposes the Werkzeug interactive debugger.
    app.run(debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true")
