#!/usr/bin/env python3
import os
import json
import sqlite3
import glob
import requests

# Determine repository root and project directory.
repo_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
proj_dir = os.path.join(repo_root, "proj")
db_path = os.path.join(proj_dir, "result.db")

# Get list of JSON files in {repo}/proj/ directory.
json_files = glob.glob(os.path.join(proj_dir, "*.json"))

# Discord webhook URL (must be set in environment variables)
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL")
if not DISCORD_WEBHOOK_URL:
    print("DISCORD_WEBHOOK_URL is not set.")
    exit(1)

def send_discord_notification(team, message):
    """Send a Discord notification with the team name and message."""
    full_message = f"**{team}**: {message}"
    data = {"content": full_message}
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=data)
        if response.status_code not in (200, 204):
            print(f"Failed to send Discord notification: {response.text}")
    except Exception as e:
        print(f"Error sending Discord notification: {e}")

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
    """
    c = conn.cursor()
    # Build a set of keys from the JSON file.
    json_keys = set()
    for entry in json_entries:
        key = tuple(entry.get(field) for field in key_fields)
        json_keys.add(key)

    # Get existing keys from DB.
    placeholders = ", ".join("?" for _ in key_fields)
    query = f"SELECT {', '.join(key_fields)} FROM {table} WHERE team_id = ?"
    c.execute(query, (team_id,))
    db_keys = set(c.fetchone() for c in c.fetchall())  # c.fetchall() returns list of tuples

    # Delete records that are not present in the JSON.
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
        # Insert new products
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
                send_discord_notification(team_name, f"New implementation product added: {name} (Version: {version})")
                c.execute("UPDATE implementation_products SET notified = 1 WHERE team_id = ? AND name = ?", (team_id, name))
                conn.commit()
        # Remove products no longer present
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
                send_discord_notification(team_name, f"New fuzzer added: {name} targeting {target} (Status: {status})")
                c.execute("UPDATE fuzzing_fuzzers SET notified = 1 WHERE team_id = ? AND name = ? AND target = ?", (team_id, name, target))
                conn.commit()
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
            send_discord_notification(team_name, f"New auditing target added: {name} (Status: {status})")
            c.execute("UPDATE auditing_targets SET notified = 1 WHERE team_id = ? AND name = ?", (team_id, name))
            conn.commit()
        # Remove auditing target if changed (since only one target is expected, we simply delete if different)
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
        # Remove milestones that no longer apply
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
                    send_discord_notification(team_name, f"Accumulated crash milestone reached: {milestone} crashes")

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
                    send_discord_notification(team_name, f"New report added: {link}")
                    c.execute("UPDATE reporting_reports SET notified = 1 WHERE team_id = ? AND link = ?", (team_id, link))
                    conn.commit()
            sync_section(conn, team_id, "reporting_reports", ("link",), json_reports)

            # Check report count for milestones.
            c.execute("SELECT COUNT(*) FROM reporting_reports WHERE team_id = ?", (team_id,))
            report_count = c.fetchone()[0]
            # Remove milestone records that are higher than current count.
            c.execute("DELETE FROM reporting_report_milestones WHERE team_id = ? AND milestone > ?", (team_id, report_count))
            conn.commit()
            report_milestones = [1, 5, 10, 15, 20, 25]  # Example milestones; adjust as needed.
            for milestone in report_milestones:
                if report_count >= milestone:
                    c.execute("SELECT id FROM reporting_report_milestones WHERE team_id = ? AND milestone = ?", (team_id, milestone))
                    if not c.fetchone():
                        c.execute(
                            "INSERT INTO reporting_report_milestones (team_id, milestone, notified) VALUES (?, ?, ?)",
                            (team_id, milestone, 1)
                        )
                        conn.commit()
                        send_discord_notification(team_name, f"Report milestone reached: {milestone} reports")

        # Process CVE entries.
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
                    send_discord_notification(team_name, f"New CVE added: {link}")
                    c.execute("UPDATE reporting_cves SET notified = 1 WHERE team_id = ? AND link = ?", (team_id, link))
                    conn.commit()
            sync_section(conn, team_id, "reporting_cves", ("link",), json_cves)

    # --- Submissions: Process conference and paper submissions ---
    if "submissions" in data:
        submissions = data["submissions"]

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
                    send_discord_notification(team_name, f"New conference submission: {title} at {venue}")
                    c.execute("UPDATE submissions_conference SET notified = 1 WHERE team_id = ? AND venue = ? AND title = ?", (team_id, venue, title))
                    conn.commit()
            sync_section(conn, team_id, "submissions_conference", ("venue", "title"), json_confs)

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
                    send_discord_notification(team_name, f"New paper submission: {title} at {venue}")
                    c.execute("UPDATE submissions_paper SET notified = 1 WHERE team_id = ? AND venue = ? AND title = ?", (team_id, venue, title))
                    conn.commit()
            sync_section(conn, team_id, "submissions_paper", ("venue", "title"), json_papers)

def main():
    conn = sqlite3.connect(db_path)
    for file_path in json_files:
        process_json_file(conn, file_path)
    conn.close()

if __name__ == '__main__':
    main()

