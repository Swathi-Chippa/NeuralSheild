import pickle
import numpy as np
from feature_extraction import extract_features

model = pickle.load(open("model/phishing_model.pkl","rb"))

url = input("Enter URL: ")

features = extract_features(url)

features = np.array(features).reshape(1,-1)

prediction = model.predict(features)

if prediction[0] == -1:
    print("⚠️ Phishing Website Detected")
else:
    print("✅ Legitimate Website")