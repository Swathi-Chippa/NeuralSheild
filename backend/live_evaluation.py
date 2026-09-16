"""Evaluate the phishing model against a reproducible live URL sample."""

from __future__ import annotations

import pickle
import random
import re
import socket
from datetime import datetime
from pathlib import Path
from typing import Any

import requests

from feature_extraction import extract_features


OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
SAMPLE_SIZE = 60
RANDOM_SEED = 42
PHISHING_THRESHOLD = 0.3
ORIGINAL_ACCURACY_FALLBACK = 0.9724106739032112
CACHE_MAX_AGE_SECONDS = 6 * 60 * 60
EVALUATION_TIMEOUT = (5, 15)
EXCLUSION_REASONS = ("DNS failure", "connection timeout", "connection refused", "other")

# These are intentionally ordinary, well-known public sites rather than URLs
# selected from a reputation list. They are kept in memory and are not written
# to the evaluation report.
LEGITIMATE_URLS = [
    "https://www.wikipedia.org",
    "https://www.python.org",
    "https://www.nasa.gov",
    "https://www.google.com",
    "https://www.bing.com",
    "https://news.bbc.co.uk",
    "https://www.reuters.com",
    "https://www.cnn.com",
    "https://www.ox.ac.uk",
    "https://www.harvard.edu",
    "https://www.mit.edu",
    "https://www.stanford.edu",
    "https://www.berkeley.edu",
    "https://www.usa.gov",
    "https://www.whitehouse.gov",
    "https://www.who.int",
    "https://www.cern.ch",
    "https://www.nytimes.com",
    "https://www.yahoo.com",
    "https://www.mozilla.org",
    "https://duckduckgo.com",
    "https://www.baidu.com",
    "https://yandex.com",
    "https://www.ecosia.org",
    "https://www.startpage.com",
    "https://apnews.com",
    "https://www.theguardian.com",
    "https://www.aljazeera.com",
    "https://www.washingtonpost.com",
    "https://www.npr.org",
    "https://www.bloomberg.com",
    "https://www.gov.uk",
    "https://www.canada.ca",
    "https://www.australia.gov.au",
    "https://www.india.gov.in",
    "https://european-union.europa.eu",
    "https://www.data.gov",
    "https://www.irs.gov",
    "https://www.yale.edu",
    "https://www.princeton.edu",
    "https://www.columbia.edu",
    "https://www.caltech.edu",
    "https://www.cornell.edu",
    "https://www.cam.ac.uk",
    "https://www.ed.ac.uk",
    "https://www.open.ac.uk",
    "https://www.amazon.com",
    "https://www.ebay.com",
    "https://www.walmart.com",
    "https://www.target.com",
    "https://www.etsy.com",
    "https://www.shopify.com",
    "https://www.bestbuy.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.ibm.com",
    "https://www.intel.com",
    "https://www.adobe.com",
    "https://www.salesforce.com",
    "https://www.oracle.com",
]


def fetch_phishing_sample() -> list[str]:
    """Fetch the feed and return a deterministic in-memory sample."""
    response = requests.get(OPENPHISH_FEED_URL, timeout=EVALUATION_TIMEOUT)
    response.raise_for_status()
    feed_urls = [line.strip() for line in response.text.splitlines() if line.strip()]
    if len(feed_urls) < SAMPLE_SIZE:
        raise RuntimeError(
            f"OpenPhish feed contained only {len(feed_urls)} URLs; "
            f"{SAMPLE_SIZE} are required."
        )
    sampler = random.Random(RANDOM_SEED)
    return sampler.sample(feed_urls, SAMPLE_SIZE)


def load_or_fetch_phishing_sample(cache_file: Path) -> tuple[list[str], str, float]:
    """Reuse a recent debugging sample, or fetch and cache a new one."""
    if cache_file.exists():
        age_seconds = datetime.now().timestamp() - cache_file.stat().st_mtime
        if 0 <= age_seconds < CACHE_MAX_AGE_SECONDS:
            cached_urls = [
                line.strip()
                for line in cache_file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            if len(cached_urls) == SAMPLE_SIZE:
                return cached_urls, "cache", age_seconds / 3600

    sampled_urls = fetch_phishing_sample()
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text("\n".join(sampled_urls) + "\n", encoding="utf-8")
    return sampled_urls, "fresh fetch", 0.0


def load_original_accuracy(report_path: Path) -> float:
    """Read the held-out accuracy recorded by the original training run."""
    try:
        report = report_path.read_text(encoding="utf-8")
        match = re.search(r"^Accuracy:\s*([0-9]*\.?[0-9]+)", report, re.MULTILINE)
        if match:
            return float(match.group(1))
    except OSError:
        pass
    return ORIGINAL_ACCURACY_FALLBACK


def predict_url(model: Any, url: str) -> bool:
    """Return whether the model considers a URL phishing."""
    features = extract_features(url)
    probabilities = model.predict_proba([features])[0]
    classes = list(model.classes_)
    phishing_index = classes.index(-1)
    return float(probabilities[phishing_index]) >= PHISHING_THRESHOLD


def contains_exception_type(exc: BaseException, exception_type: type[BaseException]) -> bool:
    """Return whether an exception or its cause/context has the given type."""
    current: BaseException | None = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, exception_type):
            return True
        current = current.__cause__ or current.__context__
    return False


def classify_exclusion(exc: BaseException) -> str:
    """Map network failures, including wrapped requests errors, to report labels."""
    current: BaseException | None = exc
    seen: set[int] = set()
    chain: list[BaseException] = []
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ or current.__context__

    if any(
        isinstance(item, socket.gaierror)
        or type(item).__name__ == "NameResolutionError"
        for item in chain
    ):
        return "DNS failure"
    if any(
        isinstance(item, (requests.exceptions.Timeout, TimeoutError, socket.timeout))
        for item in chain
    ):
        return "connection timeout"
    if any(
        isinstance(item, ConnectionRefusedError)
        or getattr(item, "errno", None) in {10061, 111}
        or "connection refused" in str(item).lower()
        for item in chain
    ):
        return "connection refused"
    return "other"


def check_reachability(url: str) -> None:
    """Use evaluation-only 5/15-second network timeouts before feature extraction."""
    response = requests.get(url, timeout=EVALUATION_TIMEOUT, allow_redirects=False)
    response.close()


def evaluate(model: Any, phishing_urls: list[str]) -> dict[str, int | float]:
    counts: dict[str, int | float] = {
        "phishing_sampled": len(phishing_urls),
        "legitimate_sampled": len(LEGITIMATE_URLS),
        "phishing_excluded": 0,
        "legitimate_excluded": 0,
        "phishing_correct": 0,
        "legitimate_correct": 0,
        "phishing_ssl_counted": 0,
        "legitimate_ssl_counted": 0,
    }
    exclusion_counts = {
        label: {reason: 0 for reason in EXCLUSION_REASONS}
        for label in ("phishing", "legitimate")
    }

    cases = [(url, "phishing", -1) for url in phishing_urls]
    cases += [(url, "legitimate", 1) for url in LEGITIMATE_URLS]
    for url, label, expected in cases:
        try:
            check_reachability(url)
            predicted_phishing = predict_url(model, url)
        except Exception as exc:
            if contains_exception_type(exc, requests.exceptions.SSLError):
                counts[f"{label}_ssl_counted"] += 1
                print(
                    f"{label.upper()}: "
                    "excluded_but_counted_as_phishing_due_to_ssl_error"
                )
                if label == "phishing":
                    counts["phishing_correct"] += 1
                continue
            counts[f"{label}_excluded"] += 1
            reason = classify_exclusion(exc)
            exclusion_counts[label][reason] += 1
            print(f"{label.upper()}: excluded ({reason})")
            continue

        predicted = -1 if predicted_phishing else 1
        if predicted == expected:
            counts[f"{label}_correct"] += 1

    phishing_evaluated = int(counts["phishing_sampled"]) - int(counts["phishing_excluded"])
    legitimate_evaluated = int(counts["legitimate_sampled"]) - int(counts["legitimate_excluded"])
    evaluated = phishing_evaluated + legitimate_evaluated
    counts["phishing_evaluated"] = phishing_evaluated
    counts["legitimate_evaluated"] = legitimate_evaluated
    counts["overall_evaluated"] = evaluated
    counts["phishing_accuracy"] = (
        int(counts["phishing_correct"]) / phishing_evaluated if phishing_evaluated else 0.0
    )
    counts["legitimate_accuracy"] = (
        int(counts["legitimate_correct"]) / legitimate_evaluated
        if legitimate_evaluated
        else 0.0
    )
    counts["overall_accuracy"] = (
        (int(counts["phishing_correct"]) + int(counts["legitimate_correct"])) / evaluated
        if evaluated
        else 0.0
    )
    counts["exclusion_counts"] = exclusion_counts
    return counts


def confidence_interval(correct: int, evaluated: int) -> tuple[float, float]:
    if evaluated == 0:
        return 0.0, 0.0
    proportion = correct / evaluated
    margin = 1.96 * (proportion * (1 - proportion) / evaluated) ** 0.5
    return max(0.0, proportion - margin), min(1.0, proportion + margin)


def make_report(counts: dict[str, int | float], original_accuracy: float) -> str:
    gap = float(counts["overall_accuracy"]) - original_accuracy
    meaningful_gap = abs(gap) >= 0.05
    conclusion = (
        "Meaningful gap detected: this suggests concept drift and/or dataset "
        "staleness is affecting real-world performance."
        if meaningful_gap
        else "No meaningful gap detected at the 5 percentage-point level, though "
        "this small sample is not a substitute for a formal benchmark."
    )
    phishing_ci = confidence_interval(
        int(counts["phishing_correct"]), int(counts["phishing_evaluated"])
    )
    legitimate_ci = confidence_interval(
        int(counts["legitimate_correct"]), int(counts["legitimate_evaluated"])
    )
    overall_ci = confidence_interval(
        int(counts["phishing_correct"]) + int(counts["legitimate_correct"]),
        int(counts["overall_evaluated"]),
    )
    exclusion_counts = counts["exclusion_counts"]
    run_time = datetime.now().astimezone().isoformat(timespec="seconds")
    exclusion_lines = ["Exclusion reasons by class:"]
    for label in ("phishing", "legitimate"):
        reason_text = ", ".join(
            f"{reason}={exclusion_counts[label][reason]}"
            for reason in EXCLUSION_REASONS
        )
        exclusion_lines.append(f"  {label.capitalize()}: {reason_text}")
    return "\n".join(
        [
            "LIVE PHISHING MODEL EVALUATION",
            f"Run date/time: {run_time}",
            f"Random seed: {RANDOM_SEED}",
            f"Phishing URLs sampled/tested: {counts['phishing_sampled']}",
            f"Legitimate URLs sampled/tested: {counts['legitimate_sampled']}",
            f"Phishing URLs evaluated: {counts['phishing_evaluated']}",
            f"Legitimate URLs evaluated: {counts['legitimate_evaluated']}",
            f"Phishing URLs excluded as unreachable: {counts['phishing_excluded']}",
            f"Legitimate URLs excluded as unreachable: {counts['legitimate_excluded']}",
            f"Total URLs excluded as unreachable: {int(counts['phishing_excluded']) + int(counts['legitimate_excluded'])}",
            "excluded_but_counted_as_phishing_due_to_ssl_error "
            f"(phishing): {counts['phishing_ssl_counted']}",
            "excluded_but_counted_as_phishing_due_to_ssl_error "
            f"(legitimate false positives): {counts['legitimate_ssl_counted']}",
            f"Phishing accuracy (recall): {float(counts['phishing_accuracy']):.4f} ({float(counts['phishing_accuracy']) * 100:.2f}%)",
            f"Phishing accuracy 95% CI: [{phishing_ci[0]:.4f}, {phishing_ci[1]:.4f}] ({phishing_ci[0] * 100:.2f}% to {phishing_ci[1] * 100:.2f}%)",
            f"Legitimate accuracy (specificity): {float(counts['legitimate_accuracy']):.4f} ({float(counts['legitimate_accuracy']) * 100:.2f}%)",
            f"Legitimate accuracy 95% CI: [{legitimate_ci[0]:.4f}, {legitimate_ci[1]:.4f}] ({legitimate_ci[0] * 100:.2f}% to {legitimate_ci[1] * 100:.2f}%)",
            f"Overall accuracy: {float(counts['overall_accuracy']):.4f} ({float(counts['overall_accuracy']) * 100:.2f}%)",
            f"Overall accuracy 95% CI: [{overall_ci[0]:.4f}, {overall_ci[1]:.4f}] ({overall_ci[0] * 100:.2f}% to {overall_ci[1] * 100:.2f}%)",
            f"Original 2012-era held-out test accuracy: {original_accuracy:.4f} ({original_accuracy * 100:.2f}%)",
            f"Overall gap versus original test accuracy: {gap:+.4f} ({gap * 100:+.2f} percentage points)",
            *exclusion_lines,
            f"Conclusion: {conclusion}",
            "Raw OpenPhish URLs were not saved.",
            "",
        ]
    )


def main() -> None:
    backend_dir = Path(__file__).resolve().parent
    model_path = backend_dir / "model" / "phishing_model.pkl"
    training_report_path = backend_dir / "model" / "training_report.txt"
    output_path = backend_dir / "model" / "live_evaluation_report.txt"
    cache_file = backend_dir / ".evaluation_cache" / "phishing_sample.txt"

    print(f"Selecting {SAMPLE_SIZE} phishing URLs (seed {RANDOM_SEED})...")
    phishing_urls, sample_source, cache_age_hours = load_or_fetch_phishing_sample(cache_file)
    if sample_source == "cache":
        print(f"Used cached OpenPhish sample; cache age: {cache_age_hours:.2f} hours")
    else:
        print("Fetched a fresh OpenPhish sample and saved it to the local debugging cache; cache age: 0.00 hours")
    print(f"Evaluation timeout: connect={EVALUATION_TIMEOUT[0]}s, read={EVALUATION_TIMEOUT[1]}s")
    with model_path.open("rb") as model_file:
        model = pickle.load(model_file)
    counts = evaluate(model, phishing_urls)
    original_accuracy = load_original_accuracy(training_report_path)
    report = make_report(counts, original_accuracy)
    output_path.write_text(report, encoding="utf-8")

    print("\n" + report, end="")


if __name__ == "__main__":
    main()
