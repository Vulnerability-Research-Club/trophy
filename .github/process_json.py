#!/usr/bin/env python3
import os
import json
import sqlite3
import glob
import requests

# Set the Discord webhook URL.
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1350341781375418369/IbDsHj8nqO4DLXl3NnFhUTX_QumkZ-xjbNoDS9rVGikKOK_uHh5mJ30AWDV94qzsssDx"

# Determine repository root and project directory.
repo_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
proj_dir = os.path.join(repo_root, "proj")
db_path = os.path.join(proj_dir, "result.db")

# Get list of JSON files in {repo}/proj/ directory.
json_files = glob.glob(os.path.join(proj_dir, "*.json"))

# Mapping from category key to Korean name (for non-report types).
KOREAN_CATEGORY = {
    "auditing": "오디팅",
    "fuzzing": "퍼징",
    "implementation": "구현",
    "submissions": "학회제출"
}

def notify_trophy(team_name, category, count):
    """
    Send a Discord notification with an image for the given trophy event.
    Uses multipart/form-data POST (mimicking the provided curl command).

    team_name: team name (from JSON filename, uppercase)
    category: one of the following:
              "auditing", "fuzzing", "implementation", "report", "cve", "submissions", "crash"
    count: count of the entity (must be > 0)
    """
    if count <= 0:
        return

    image_filename = f"{category}.jpg"
    path_to_category_image = os.path.join(repo_root, "image", image_filename)

    if category == "report":
        description = f"{count}번째 제보을(를) 수행하였습니다."
    elif category == "cve":
        description = f"축하합니다! {count}번째 CVE을(를) 받았습니다."
    elif category == "crash":
        description = f"{count}번째 crash을(를) 찾았습니다."
    else:
        korean_category = KOREAN_CATEGORY.get(category, category)
        description = f"{count}번째 {korean_category}을(를) 수행하였습니다."

    payload = {
        "embeds": [{
            "title": f"**{team_name}**",
            "description": description,
            "color": 16711680,
            "thumbnail": {"url": f"attachment://{image_filename}"}
        }]
    }

    files = {
        "payload_json": (None, json.dumps(payload)),
        "file": (image_filename, open(path_to_category_image, "rb"), "image/jpeg")
    }

    response = requests.post(DISCORD_WEBHOOK_URL, files=files)
    if response.status_code not in (200, 204):
        print(f"Discord notification failed: {response.text}")

def get_or_create_team(conn, team_name):
    c = conn.cursor()
    c.execute("SELECT id FROM teams WHERE name = ?", (team_name,))
    row = c.fetchone()
    if row:
        return row[0]
    c.execute("INSERT INTO teams (name) VALUES (?)", (team_name,))
    conn.commit()
    return c.lastrowid

def sync_section(conn, team_id, table, key_fields, json_entries):
    c = conn.cursor()
    json_keys = set()
    for entry in json_entries:
        key = tuple(entry.get(field).strip() if isinstance(entry.get(field), str) else entry.get(field) for field in key_fields)
        json_keys.add(key)

    c.execute(f"SELECT {', '.join(key_fields)} FROM {table} WHERE team_id = ?", (team_id,))
    db_rows = c.fetchall()
    db_keys = set(tuple(row) for row in db_rows)

    for db_key in db_keys:
        if db_key not in json_keys:
            where_clause = " AND ".join(f"{field} = ?" for field in key_fields)
            c.execute(f"DELETE FROM {table} WHERE team_id = ? AND {where_clause}", (team_id, *db_key))
            conn.commit()

def process_json_file(conn, file_path):
    team_name = os.path.splitext(os.path.basename(file_path))[0].upper()
    team_id = get_or_create_team(conn, team_name)

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    c = conn.cursor()

    # --- Implementation: Process products ---
    if "implementation" in data and "product" in data["implementation"]:
        json_products = data["implementation"]["product"]
        for product in json_products:
            name = product.get("name").strip()
            description = product.get("description")
            version = product.get("version")
            c.execute("SELECT id FROM implementation_products WHERE team_id = ? AND name = ?", (team_id, name))
            if not c.fetchone():
                c.execute(
                    "INSERT INTO implementation_products (team_id, name, description, version, notified) VALUES (?, ?, ?, ?, ?)",
                    (team_id, name, description, version, 0)
                )
                conn.commit()
                c.execute("SELECT COUNT(*) FROM implementation_products WHERE team_id = ?", (team_id,))
                count = c.fetchone()[0]
                notify_trophy(team_name, "implementation", count)
        sync_section(conn, team_id, "implementation_products", ("name",), json_products)

    # --- Fuzzing: Process fuzzers ---
    if "fuzzing" in data and "fuzzer" in data["fuzzing"]:
        json_fuzzers = data["fuzzing"]["fuzzer"]
        for fuzzer in json_fuzzers:
            name = fuzzer.get("name").strip()
            target = fuzzer.get("target").strip()
            description = fuzzer.get("description")
            status = fuzzer.get("status")
            c.execute("SELECT id FROM fuzzing_fuzzers WHERE team_id = ? AND name = ? AND target = ?", (team_id, name, target))
            if not c.fetchone():
                c.execute(
                    "INSERT INTO fuzzing_fuzzers (team_id, name, target, description, status, notified) VALUES (?, ?, ?, ?, ?, ?)",
                    (team_id, name, target, description, status, 0)
                )
                conn.commit()
                c.execute("SELECT COUNT(*) FROM fuzzing_fuzzers WHERE team_id = ?", (team_id,))
                count = c.fetchone()[0]
                notify_trophy(team_name, "fuzzing", count)
        sync_section(conn, team_id, "fuzzing_fuzzers", ("name", "target"), json_fuzzers)

    # --- Auditing: Process target ---
    if "auditing" in data and "target" in data["auditing"]:
        target_data = data["auditing"]["target"]
        name = target_data.get("name", "").strip()
        status = target_data.get("status")
        if name:
            c.execute("SELECT id FROM auditing_targets WHERE team_id = ? AND name = ?", (team_id, name))
            if not c.fetchone():
                c.execute(
                    "INSERT INTO auditing_targets (team_id, name, status, notified) VALUES (?, ?, ?, ?)",
                    (team_id, name, status, 0)
                )
                conn.commit()
                notify_trophy(team_name, "auditing", 1)
        else:
            c.execute("DELETE FROM auditing_targets WHERE team_id = ?", (team_id,))
            conn.commit()

    # --- Reporting: Process crash milestones, report entries and CVEs ---
    if "reporting" in data:
        reporting = data["reporting"]

        # Process crash milestones using num_accumulated_crash.
        crash_count = reporting.get("num_accumulated_crash", 0)
        if crash_count > 0:
            milestones = []
            m = 10
            while m <= crash_count:
                milestones.append(m)
                m += 10
            for milestone in milestones:
                c.execute("SELECT id FROM reporting_crash_milestones WHERE team_id = ? AND milestone = ?", (team_id, milestone))
                if not c.fetchone():
                    c.execute(
                        "INSERT INTO reporting_crash_milestones (team_id, milestone, notified) VALUES (?, ?, ?)",
                        (team_id, milestone, 1)
                    )
                    conn.commit()
                    notify_trophy(team_name, "crash", milestone)

        # Process report entries (제보).
        if "report" in reporting:
            json_reports = reporting["report"]
            for rep in json_reports:
                link = rep.get("link").strip()
                description = rep.get("description")
                c.execute("SELECT id FROM reporting_reports WHERE team_id = ? AND link = ?", (team_id, link))
                if not c.fetchone():
                    c.execute(
                        "INSERT INTO reporting_reports (team_id, link, description, notified) VALUES (?, ?, ?, ?)",
                        (team_id, link, description, 0)
                    )
                    conn.commit()
            sync_section(conn, team_id, "reporting_reports", ("link",), json_reports)
            c.execute("SELECT COUNT(*) FROM reporting_reports WHERE team_id = ?", (team_id,))
            report_count = c.fetchone()[0]
            milestones = []
            if report_count >= 1:
                milestones.append(1)
            m = 5
            while m <= report_count:
                milestones.append(m)
                m += 5
            c.execute("DELETE FROM reporting_report_milestones WHERE team_id = ? AND milestone > ?", (team_id, report_count))
            conn.commit()
            for milestone in milestones:
                c.execute("SELECT id FROM reporting_report_milestones WHERE team_id = ? AND milestone = ?", (team_id, milestone))
                if not c.fetchone():
                    c.execute(
                        "INSERT INTO reporting_report_milestones (team_id, milestone, notified) VALUES (?, ?, ?)",
                        (team_id, milestone, 1)
                    )
                    conn.commit()
                    notify_trophy(team_name, "report", milestone)

        # Process CVE entries.
        if "cve" in reporting:
            json_cves = reporting["cve"]
            for cve in json_cves:
                link = cve.get("link").strip()
                description = cve.get("description")
                c.execute("SELECT id FROM reporting_cves WHERE team_id = ? AND link = ?", (team_id, link))
                if not c.fetchone():
                    c.execute(
                        "INSERT INTO reporting_cves (team_id, link, description, notified) VALUES (?, ?, ?, ?)",
                        (team_id, link, description, 0)
                    )
                    conn.commit()
            sync_section(conn, team_id, "reporting_cves", ("link",), json_cves)
            # Notify for each new CVE individually.
            c.execute("SELECT id FROM reporting_cves WHERE team_id = ? AND notified = 0 ORDER BY id", (team_id,))
            new_cve_rows = c.fetchall()
            for row in new_cve_rows:
                new_cve_id = row[0]
                c.execute("SELECT COUNT(*) FROM reporting_cves WHERE team_id = ? AND id <= ?", (team_id, new_cve_id))
                rank = c.fetchone()[0]
                notify_trophy(team_name, "cve", rank)
                c.execute("UPDATE reporting_cves SET notified = 1 WHERE id = ?", (new_cve_id,))
                conn.commit()

    # --- Submissions: Process conference and paper submissions together ---
    new_submission_count = 0
    if "submissions" in data:
        submissions = data["submissions"]

        if "conference" in submissions:
            json_confs = submissions["conference"]
            for conf in json_confs:
                venue = conf.get("venue").strip()
                title = conf.get("title").strip()
                c.execute("SELECT id FROM submissions_conference WHERE team_id = ? AND venue = ? AND title = ?", (team_id, venue, title))
                if not c.fetchone():
                    c.execute(
                        "INSERT INTO submissions_conference (team_id, venue, title, notified) VALUES (?, ?, ?, ?)",
                        (team_id, venue, title, 1)
                    )
                    conn.commit()
                    new_submission_count += 1
            sync_section(conn, team_id, "submissions_conference", ("venue", "title"), json_confs)

        if "paper" in submissions:
            json_papers = submissions["paper"]
            for paper in json_papers:
                venue = paper.get("venue").strip()
                title = paper.get("title").strip()
                c.execute("SELECT id FROM submissions_paper WHERE team_id = ? AND venue = ? AND title = ?", (team_id, venue, title))
                if not c.fetchone():
                    c.execute(
                        "INSERT INTO submissions_paper (team_id, venue, title, notified) VALUES (?, ?, ?, ?)",
                        (team_id, venue, title, 1)
                    )
                    conn.commit()
                    new_submission_count += 1
            sync_section(conn, team_id, "submissions_paper", ("venue", "title"), json_papers)

        if new_submission_count > 0:
            c.execute("SELECT COUNT(*) FROM submissions_conference WHERE team_id = ?", (team_id,))
            conf_total = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM submissions_paper WHERE team_id = ?", (team_id,))
            paper_total = c.fetchone()[0]
            overall_total = conf_total + paper_total
            notify_trophy(team_name, "submissions", overall_total)

def main():
    conn = sqlite3.connect(db_path)
    for file_path in json_files:
        process_json_file(conn, file_path)
    conn.close()

if __name__ == '__main__':
    main()
