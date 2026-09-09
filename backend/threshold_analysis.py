import pickle

import pandas as pd
from sklearn.metrics import precision_recall_curve
from sklearn.model_selection import train_test_split


data = pd.read_csv("datasets/phishing.csv")
X = data.drop(["index", "Result"], axis=1)
y = data["Result"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y,
)

with open("model/phishing_model.pkl", "rb") as model_file:
    model = pickle.load(model_file)

phishing_class_index = list(model.classes_).index(-1)
proba_phishing = model.predict_proba(X_test)[:, phishing_class_index]
precision, recall, thresholds = precision_recall_curve(
    y_test,
    proba_phishing,
    pos_label=-1,
)

target_thresholds = [0.9, 0.7, 0.5, 0.4, 0.3, 0.2, 0.1]
phishing_total = int((y_test == -1).sum())
legitimate_total = int((y_test == 1).sum())

print("=== PHISHING THRESHOLD ANALYSIS ===")
print(f"Test-set phishing sites (-1): {phishing_total}")
print(f"Test-set legitimate sites (1): {legitimate_total}")
print("Precision/recall use pos_label=-1 (phishing).")
print("Counts use the closest available threshold returned by precision_recall_curve.")
print()
print(
    f"{'Requested':>10} {'Used':>12} {'Precision':>12} {'Recall':>12} "
    f"{'Phishing FN':>14} {'Legitimate FP':>16}"
)
print("-" * 80)

for target in target_thresholds:
    threshold_index = min(
        range(len(thresholds)),
        key=lambda index: abs(float(thresholds[index]) - target),
    )
    used_threshold = float(thresholds[threshold_index])
    predicted_phishing = proba_phishing >= used_threshold
    false_negatives = sum(
        actual == -1 and not predicted
        for actual, predicted in zip(y_test.tolist(), predicted_phishing)
    )
    false_positives = sum(
        actual == 1 and predicted
        for actual, predicted in zip(y_test.tolist(), predicted_phishing)
    )
    print(
        f"{target:10.1f} {used_threshold:12.6f} "
        f"{precision[threshold_index]:12.6f} {recall[threshold_index]:12.6f} "
        f"{false_negatives:14d} {false_positives:16d}"
    )
