from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import numpy as np
from feature_extraction import extract_features

app = Flask(__name__)
CORS(app)   # ⭐ this line fixes the problem

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
    app.run(debug=True)