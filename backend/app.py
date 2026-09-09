from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import pickle
import numpy as np
from feature_extraction import extract_features

app = Flask(__name__)
# Update these origins if the frontend is deployed elsewhere.
CORS(app, origins=["http://localhost:5173", "http://127.0.0.1:5173"])

model = pickle.load(open("model/phishing_model.pkl", "rb"))

@app.route("/predict", methods=["POST"])
def predict():

    data = request.json
    url = data["url"]

    features = extract_features(url)
    features = np.array(features).reshape(1,-1)

    prediction = model.predict(features)

    if prediction[0] == -1:
        result = "Phishing Website"
    else:
        result = "Legitimate Website"

    return jsonify({"prediction": result})


if __name__ == "__main__":
    # debug=True must never be used outside local development because it exposes the Werkzeug interactive debugger.
    app.run(debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true")
