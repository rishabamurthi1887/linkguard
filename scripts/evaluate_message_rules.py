"""Evaluate the current deterministic message rules on the synthetic held-out set."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.main import analyze_message_text


def score(rows):
    tp = fp = fn = tn = 0
    groups = {}
    errors = []
    for row in rows:
        actual = row["label"] == "scam_like"
        predicted = bool(analyze_message_text(row["text"])["evidence"])
        tp += actual and predicted
        fp += (not actual) and predicted
        fn += actual and (not predicted)
        tn += (not actual) and (not predicted)
        groups.setdefault(row["language"], []).append((actual, predicted))
        groups.setdefault("category:" + row["category"], []).append((actual, predicted))
        if actual != predicted:
            errors.append({"id":row["id"],"language":row["language"],"label":row["label"],"predicted":"scam_like" if predicted else "legitimate_like"})
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None
    return {"n":len(rows),"tp":tp,"fp":fp,"fn":fn,"tn":tn,"precision":precision,"recall":recall,"f1":f1,"false_positive_rate":fp/(fp+tn) if fp+tn else None,"false_negative_rate":fn/(fn+tp) if fn+tp else None,"groups":{name:{"n":len(values),"correct":sum(actual==predicted for actual,predicted in values)} for name,values in sorted(groups.items())},"errors":errors}


def main():
    rows=[]
    for path in sorted((ROOT / "tests" / "data" / "test").glob("*.jsonl")):
        rows.extend(json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    print(json.dumps({"evaluation":"synthetic held-out rule check; not real-world accuracy","dataset_version":"1.0.0","results":score(rows)},ensure_ascii=False,indent=2))


if __name__ == "__main__":
    main()
