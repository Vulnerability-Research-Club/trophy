#!/usr/bin/env python3
import os
import json
import sqlite3
import glob
import requests
import json

# Set the Discord webhook URL to the provided URL.
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1350341781375418369/IbDsHj8nqO4DLXl3NnFhUTX_QumkZ-xjbNoDS9rVGikKOK_uHh5mJ30AWDV94qzsssDx"

# Determine repository root and project directory.
repo_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
proj_dir = os.path.join(repo_root, "proj")
db_path = os.path.join(proj_dir, "result.db")

# Get list of JSON files in {repo}/proj/ directory.
json_files = glob.glob(os.path.join(proj_dir, "*.json"))

# Define a mapping from category key to Korean category name.
KOREAN_CATEGORY = {
    "auditing": "오디팅",
    "fuzzing": "퍼징",
    "implementation": "구현",
    "reporting": "제보",
    "submissions": "학회제출"
}

def notify_trophy(team_name, category, count):
    """
    Send a Discord notification with an image for the given trophy event.
    Uses multipart/form-data POST (like the provided curl command).

    team_name: team name (from json filename, uppercase)
    category: one of the keys in KOREAN_CATEGORY (auditing, fuzzing, implementation, reporting, submissions)
    count: count of the entity in the category
    """
    # Determine the image filename and path.
    image_filename = f"{category}.jpg"
    path_to_category_image = os.path.join(repo_root, "image", image_filename)

    # Get the Korean name for the category.
    korean_category = KOREAN_CATEGORY.get(category, category)

    # Compose the description text.
    description = f"{count}번째 {korean_category}을(를) 수행하였습니다."

    # Build payload JSON (as a string) following the given format.
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
    """Get the team id from DB or create a new team record."""
    c = conn.cursor()
    c.execute("SELECT id FROM teams WHERE name = ?", (team_name,))
    row = c.fetchone()
    if row:
        return row[0]
    c.execute("INSERT INTO teams (name) VALUES (?)", (team_name,))
    conn.commit()
    return c.lastrowid

def sync_section(conn, team_id, table, key_fields, json_entries):
    """
    Synchronize a section (e.g., implementation_products) for a team.
    - key_fields: tuple of field names to uniquely identify an entry.
    - json_entries: list of dictionaries from the JSON file.
    Removes DB records that are not present in the JSON.
    """
    c = conn.cursor()
    json_keys = set()
    for entry in json_entries:
        key = tuple(entry.get(field) for field in key_fields)
        json_keys.add(key)

    # Retrieve existing keys from DB.
    c.execute(f"SELECT {', '.join(key_fields)} FROM {table} WHERE team_id = ?", (team_id,))
    db_rows = c.fetchall()
    db_keys = set(tuple(row) for row in db_rows)

    for db_key in db_keys:
        if db_key not in json_keys:
            where_clause = " AND ".join(f"{field} = ?" for field in key_fields)
            c.execute(f"DELETE FROM {table} WHERE team_id = ? AND {where_clause}", (team_id, *db_key))
            conn.commit()

def process_json_file(conn, file_path):
    """Parse a JSON file, update DB (insert new, remove missing), and send notifications for new trophies."""
    team_name = os.path.splitext(os.path.basename(file_path))[0].upper()
    team_id = get_or_create_team(conn, team_name)

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    c = conn.cursor()

    # --- Implementation: Process products ---
    if "implementation" in data and "product" in data["implementation"]:
        json_products = data["implementation"]["product"]
        for product in json_products:
            name = product.get("name")
            description = product.get("description")
            version = product.get("version")
            c.execute("SELECT id FROM implementation_products WHERE team_id = ? AND name = ?", (team_id, name))
            if not c.fetchone():
                c.execute(
                    "INSERT INTO implementation_products (team_id, name, description, version, notified) VALUES (?, ?, ?, ?, ?)",
                    (team_id, name, description, version, 0)
                )
                conn.commit()
                # Get updated count and notify.
                c.execute("SELECT COUNT(*) FROM implementation_products WHERE team_id = ?", (team_id,))
                count = c.fetchone()[0]
                notify_trophy(team_name, "implementation", count)
        sync_section(conn, team_id, "implementation_products", ("name",), json_products)

    # --- Fuzzing: Process fuzzers ---
    if "fuzzing" in data and "fuzzer" in data["fuzzing"]:
        json_fuzzers = data["fuzzing"]["fuzzer"]
        for fuzzer in json_fuzzers:
            name = fuzzer.get("name")
            target = fuzzer.get("target")
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
        name = target_data.get("name")
        status = target_data.get("status")
        c.execute("SELECT id FROM auditing_targets WHERE team_id = ? AND name = ?", (team_id, name))
        if not c.fetchone():
            c.execute(
                "INSERT INTO auditing_targets (team_id, name, status, notified) VALUES (?, ?, ?, ?)",
                (team_id, name, status, 0)
            )
            conn.commit()
            # For auditing, count is assumed to be 1.
            notify_trophy(team_name, "auditing", 1)
        # Remove auditing target if missing.
        c.execute("SELECT name FROM auditing_targets WHERE team_id = ?", (team_id,))
        db_targets = {row[0] for row in c.fetchall()}
        if name not in db_targets:
            c.execute("DELETE FROM auditing_targets WHERE team_id = ?", (team_id,))
            conn.commit()

    # --- Reporting: Process crash milestones, reports, and CVEs ---
    if "reporting" in data:
        reporting = data["reporting"]

        # Process accumulated crash milestones.
        num_crash = reporting.get("num_accumulated_crash", 0)
        crash_milestones = [1, 10, 100, 200, 300]
        c.execute("DELETE FROM reporting_crash_milestones WHERE team_id = ? AND milestone > ?", (team_id, num_crash))
        conn.commit()
        for milestone in crash_milestones:
            if num_crash >= milestone:
                c.execute("SELECT id FROM reporting_crash_milestones WHERE team_id = ? AND milestone = ?", (team_id, milestone))
                if not c.fetchone():
                    c.execute(
                        "INSERT INTO reporting_crash_milestones (team_id, milestone, notified) VALUES (?, ?, ?)",
                        (team_id, milestone, 1)
                    )
                    conn.commit()
                    notify_trophy(team_name, "reporting", milestone)

        # Process report entries.
        if "report" in reporting:
            json_reports = reporting["report"]
            for rep in json_reports:
                link = rep.get("link")
                description = rep.get("description")
                c.execute("SELECT id FROM reporting_reports WHERE team_id = ? AND link = ?", (team_id, link))
                if not c.fetchone():
                    c.execute(
                        "INSERT INTO reporting_reports (team_id, link, description, notified) VALUES (?, ?, ?, ?)",
                        (team_id, link, description, 0)
                    )
                    conn.commit()
                    c.execute("SELECT COUNT(*) FROM reporting_reports WHERE team_id = ?", (team_id,))
                    count = c.fetchone()[0]
                    # Only notify when reaching milestones (1, 5, 10, 15, etc.)
                    if count in [1, 5, 10, 15, 20, 25]:
                        notify_trophy(team_name, "reporting", count)
            sync_section(conn, team_id, "reporting_reports", ("link",), json_reports)

            # Remove report milestone records that are higher than current count.
            c.execute("SELECT COUNT(*) FROM reporting_reports WHERE team_id = ?", (team_id,))
            report_count = c.fetchone()[0]
            c.execute("DELETE FROM reporting_report_milestones WHERE team_id = ? AND milestone > ?", (team_id, report_count))
            conn.commit()
            report_milestones = [1, 5, 10, 15, 20, 25]
            for milestone in report_milestones:
                if report_count >= milestone:
                    c.execute("SELECT id FROM reporting_report_milestones WHERE team_id = ? AND milestone = ?", (team_id, milestone))
                    if not c.fetchone():
                        c.execute(
                            "INSERT INTO reporting_report_milestones (team_id, milestone, notified) VALUES (?, ?, ?)",
                            (team_id, milestone, 1)
                        )
                        conn.commit()
                        notify_trophy(team_name, "reporting", milestone)

        # Process CVE entries (treat these as part of reporting).
        if "cve" in reporting:
            json_cves = reporting["cve"]
            for cve in json_cves:
                link = cve.get("link")
                description = cve.get("description")
                c.execute("SELECT id FROM reporting_cves WHERE team_id = ? AND link = ?", (team_id, link))
                if not c.fetchone():
                    c.execute(
                        "INSERT INTO reporting_cves (team_id, link, description, notified) VALUES (?, ?, ?, ?)",
                        (team_id, link, description, 0)
                    )
                    conn.commit()
                    c.execute("SELECT COUNT(*) FROM reporting_cves WHERE team_id = ?", (team_id,))
                    count = c.fetchone()[0]
                    notify_trophy(team_name, "reporting", count)
            sync_section(conn, team_id, "reporting_cves", ("link",), json_cves)

    # --- Submissions: Process conference and paper submissions ---
    if "submissions" in data:
        submissions = data["submissions"]

        # Process conference submissions.
        if "conference" in submissions:
            json_confs = submissions["conference"]
            for conf in json_confs:
                venue = conf.get("venue")
                title = conf.get("title")
                c.execute("SELECT id FROM submissions_conference WHERE team_id = ? AND venue = ? AND title = ?", (team_id, venue, title))
                if not c.fetchone():
                    c.execute(
                        "INSERT INTO submissions_conference (team_id, venue, title, notified) VALUES (?, ?, ?, ?)",
                        (team_id, venue, title, 0)
                    )
                    conn.commit()
                    # Get the combined submission count later.
            sync_section(conn, team_id, "submissions_conference", ("venue", "title"), json_confs)

        # Process paper submissions.
        if "paper" in submissions:
            json_papers = submissions["paper"]
            for paper in json_papers:
                venue = paper.get("venue")
                title = paper.get("title")
                c.execute("SELECT id FROM submissions_paper WHERE team_id = ? AND venue = ? AND title = ?", (team_id, venue, title))
                if not c.fetchone():
                    c.execute(
                        "INSERT INTO submissions_paper (team_id, venue, title, notified) VALUES (?, ?, ?, ?)",
                        (team_id, venue, title, 0)
                    )
                    conn.commit()
            sync_section(conn, team_id, "submissions_paper", ("venue", "title"), json_papers)

        # Combined submissions count from both conference and paper.
        c.execute("SELECT COUNT(*) FROM submissions_conference WHERE team_id = ?", (team_id,))
        conf_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM submissions_paper WHERE team_id = ?", (team_id,))
        paper_count = c.fetchone()[0]
        total_submissions = conf_count + paper_count
        notify_trophy(team_name, "submissions", total_submissions)

def main():
    conn = sqlite3.connect(db_path)
    for file_path in json_files:
        process_json_file(conn, file_path)
    conn.close()

if __name__ == '__main__':
    main()
