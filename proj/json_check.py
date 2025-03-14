#!/usr/bin/env python3
import json
import sys
import os

def error(msg):
    print(f"Error: {msg}")

def validate_implementation(data):
    if "implementation" not in data:
        error("Missing 'implementation' key.")
        return False
    impl = data["implementation"]
    if "product" not in impl:
        error("Missing 'product' key in 'implementation'.")
        return False
    if not isinstance(impl["product"], list):
        error("'product' must be an array.")
        return False
    for idx, product in enumerate(impl["product"]):
        if not isinstance(product, dict):
            error(f"Product at index {idx} is not an object.")
            return False
        if "name" not in product or not isinstance(product["name"], str):
            error(f"Product at index {idx} must have a string 'name'.")
            return False
        # Optional fields: description, version
        if "description" in product and not isinstance(product["description"], str):
            error(f"Product at index {idx}: 'description' must be a string.")
            return False
        if "version" in product and not isinstance(product["version"], str):
            error(f"Product at index {idx}: 'version' must be a string.")
            return False
    return True

def validate_fuzzing(data):
    if "fuzzing" not in data:
        error("Missing 'fuzzing' key.")
        return False
    fuzz = data["fuzzing"]
    if "fuzzer" not in fuzz:
        error("Missing 'fuzzer' key in 'fuzzing'.")
        return False
    if not isinstance(fuzz["fuzzer"], list):
        error("'fuzzer' must be an array.")
        return False
    allowed_status = {"in-progress", "done"}
    for idx, fuzzer in enumerate(fuzz["fuzzer"]):
        if not isinstance(fuzzer, dict):
            error(f"Fuzzer at index {idx} is not an object.")
            return False
        if "name" not in fuzzer or not isinstance(fuzzer["name"], str):
            error(f"Fuzzer at index {idx} must have a string 'name'.")
            return False
        if "target" not in fuzzer or not isinstance(fuzzer["target"], str):
            error(f"Fuzzer at index {idx} must have a string 'target'.")
            return False
        if "status" not in fuzzer or not isinstance(fuzzer["status"], str):
            error(f"Fuzzer at index {idx} must have a string 'status'.")
            return False
        if fuzzer["status"] not in allowed_status:
            error(f"Fuzzer at index {idx}: 'status' must be one of {allowed_status}.")
            return False
        if "description" in fuzzer and not isinstance(fuzzer["description"], str):
            error(f"Fuzzer at index {idx}: 'description' must be a string.")
            return False
    return True

def validate_auditing(data):
    if "auditing" not in data:
        error("Missing 'auditing' key.")
        return False
    audit = data["auditing"]
    if "target" not in audit:
        error("Missing 'target' key in 'auditing'.")
        return False
    target = audit["target"]
    if not isinstance(target, dict):
        error("'target' in 'auditing' must be an object.")
        return False
    if "name" not in target or not isinstance(target["name"], str):
        error("Auditing 'target' must have a string 'name'.")
        return False
    if "status" not in target or not isinstance(target["status"], str):
        error("Auditing 'target' must have a string 'status'.")
        return False
    return True

def validate_reporting(data):
    if "reporting" not in data:
        error("Missing 'reporting' key.")
        return False
    rep = data["reporting"]
    if "num_accumulated_crash" not in rep:
        error("Missing 'num_accumulated_crash' in 'reporting'.")
        return False
    if not isinstance(rep["num_accumulated_crash"], (int, float)):
        error("'num_accumulated_crash' must be a number.")
        return False
    # Validate optional report array
    if "report" in rep:
        if not isinstance(rep["report"], list):
            error("'report' must be an array.")
            return False
        for idx, r in enumerate(rep["report"]):
            if not isinstance(r, dict):
                error(f"Report at index {idx} is not an object.")
                return False
            if "link" not in r or not isinstance(r["link"], str):
                error(f"Report at index {idx} must have a string 'link'.")
                return False
            if "description" in r and not isinstance(r["description"], str):
                error(f"Report at index {idx}: 'description' must be a string.")
                return False
    # Validate optional cve array
    if "cve" in rep:
        if not isinstance(rep["cve"], list):
            error("'cve' must be an array.")
            return False
        for idx, cve in enumerate(rep["cve"]):
            if not isinstance(cve, dict):
                error(f"CVE at index {idx} is not an object.")
                return False
            if "link" not in cve or not isinstance(cve["link"], str):
                error(f"CVE at index {idx} must have a string 'link'.")
                return False
            if "description" in cve and not isinstance(cve["description"], str):
                error(f"CVE at index {idx}: 'description' must be a string.")
                return False
    return True

def validate_submissions(data):
    if "submissions" not in data:
        error("Missing 'submissions' key.")
        return False
    subs = data["submissions"]
    # Validate optional conference array
    if "conference" in subs:
        if not isinstance(subs["conference"], list):
            error("'conference' must be an array.")
            return False
        for idx, conf in enumerate(subs["conference"]):
            if not isinstance(conf, dict):
                error(f"Conference at index {idx} is not an object.")
                return False
            if "venue" not in conf or not isinstance(conf["venue"], str):
                error(f"Conference at index {idx} must have a string 'venue'.")
                return False
            if "title" not in conf or not isinstance(conf["title"], str):
                error(f"Conference at index {idx} must have a string 'title'.")
                return False
    # Validate optional paper array
    if "paper" in subs:
        if not isinstance(subs["paper"], list):
            error("'paper' must be an array.")
            return False
        for idx, paper in enumerate(subs["paper"]):
            if not isinstance(paper, dict):
                error(f"Paper at index {idx} is not an object.")
                return False
            if "venue" not in paper or not isinstance(paper["venue"], str):
                error(f"Paper at index {idx} must have a string 'venue'.")
                return False
            if "title" not in paper or not isinstance(paper["title"], str):
                error(f"Paper at index {idx} must have a string 'title'.")
                return False
    return True

def validate_json_structure(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        error(f"Cannot read or parse JSON file: {e}")
        return False

    valid = True
    valid &= validate_implementation(data)
    valid &= validate_fuzzing(data)
    valid &= validate_auditing(data)
    valid &= validate_reporting(data)
    valid &= validate_submissions(data)

    if valid:
        print("JSON file is valid.")
    else:
        print("JSON file validation failed.")
    return valid

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python json_checker.py <path_to_json_file>")
        sys.exit(1)
    file_path = sys.argv[1]
    if not os.path.isfile(file_path):
        error("File does not exist.")
        sys.exit(1)
    valid = validate_json_structure(file_path)
    sys.exit(0 if valid else 1)

