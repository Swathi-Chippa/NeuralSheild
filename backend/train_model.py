import pickle

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import (
    GridSearchCV,
    StratifiedKFold,
    cross_val_score,
    train_test_split,
)


report_lines = []


def emit(message=""):
    print(message)
    report_lines.append(str(message))


emit("=== 1. DATASET LOADING ===")
data = pd.read_csv("datasets/phishing.csv")
X = data.drop(["index", "Result"], axis=1)
y = data["Result"]
emit(f"X.shape: {X.shape}")
emit("y.value_counts:")
emit(y.value_counts().to_string())

emit("=== 2. TRAIN/TEST SPLIT ===")
# stratify=y preserves the approximately 56/44 class balance in both splits.
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y,
)
emit(f"X_train.shape: {X_train.shape}")
emit(f"X_test.shape: {X_test.shape}")

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

emit("=== 3. BASELINE 5-FOLD CROSS-VALIDATION ===")
baseline_model = RandomForestClassifier(random_state=42)
baseline_scores = cross_val_score(
    baseline_model,
    X_train,
    y_train,
    cv=cv,
    scoring="f1",
)
emit(f"Baseline fold F1 scores: {baseline_scores.tolist()}")
emit(f"Baseline mean F1: {baseline_scores.mean()}")
emit(f"Baseline standard deviation: {baseline_scores.std()}")

emit("=== 4. HYPERPARAMETER GRID SEARCH ===")
grid_search = GridSearchCV(
    estimator=RandomForestClassifier(random_state=42),
    param_grid={
        "n_estimators": [100, 200],
        "max_depth": [None, 10, 20],
        "min_samples_split": [2, 5],
    },
    cv=cv,
    scoring="f1",
)
grid_search.fit(X_train, y_train)
tuned_model = grid_search.best_estimator_
emit(f"Best parameters: {grid_search.best_params_}")
emit(f"Best cross-validated F1: {grid_search.best_score_}")

emit("=== 5. HELD-OUT TEST EVALUATION ===")
y_pred = tuned_model.predict(X_test)
y_probability = tuned_model.predict_proba(X_test)
positive_class_index = list(tuned_model.classes_).index(1)
emit(f"Accuracy: {accuracy_score(y_test, y_pred)}")
emit("Classification report:")
emit(classification_report(y_test, y_pred))
emit("Confusion matrix labels: rows = actual; columns = predicted")
emit("Class order for both axes: [-1 (phishing), 1 (legitimate)]")
emit(str(confusion_matrix(y_test, y_pred, labels=[-1, 1])))
emit(
    "ROC AUC (positive class 1 / legitimate): "
    f"{roc_auc_score(y_test, y_probability[:, positive_class_index])}"
)

emit("=== 6. FEATURE IMPORTANCES ===")
feature_importances = sorted(
    zip(X.columns, tuned_model.feature_importances_),
    key=lambda item: item[1],
    reverse=True,
)
for feature_name, importance in feature_importances:
    emit(f"({feature_name}, {importance})")

emit("=== 7. MODEL SAVE ===")
with open("model/phishing_model.pkl", "wb") as model_file:
    pickle.dump(tuned_model, model_file)
emit("Saved tuned model to model/phishing_model.pkl")

emit("=== 8. TRAINING REPORT SAVE ===")
with open("model/training_report.txt", "w", encoding="utf-8") as report_file:
    report_file.write("\n".join(report_lines) + "\n")
print("Saved training report to model/training_report.txt")
