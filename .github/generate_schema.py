#!/usr/bin/env python3
import sqlite3
import os

# Determine the repository root and project directory.
# Assumes this script is located in {repo}/.github and JSON files are in {repo}/proj/
repo_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
db_path = os.path.join(repo_root, "proj", "result.db")

def init_db():
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Teams table: one row per team (JSON file)
    c.execute('''
        CREATE TABLE IF NOT EXISTS teams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE
        )
    ''')

    # Implementation products table
    c.execute('''
        CREATE TABLE IF NOT EXISTS implementation_products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id INTEGER,
            name TEXT,
            description TEXT,
            version TEXT,
            notified INTEGER DEFAULT 0,
            UNIQUE(team_id, name)
        )
    ''')

    # Fuzzing fuzzers table
    c.execute('''
        CREATE TABLE IF NOT EXISTS fuzzing_fuzzers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id INTEGER,
            name TEXT,
            target TEXT,
            description TEXT,
            status TEXT,
            notified INTEGER DEFAULT 0,
            UNIQUE(team_id, name, target)
        )
    ''')

    # Auditing targets table
    c.execute('''
        CREATE TABLE IF NOT EXISTS auditing_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id INTEGER,
            name TEXT,
            status TEXT,
            notified INTEGER DEFAULT 0,
            UNIQUE(team_id, name)
        )
    ''')

    # Reporting crash milestones table
    c.execute('''
        CREATE TABLE IF NOT EXISTS reporting_crash_milestones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id INTEGER,
            milestone INTEGER,
            notified INTEGER DEFAULT 0,
            UNIQUE(team_id, milestone)
        )
    ''')

    # Reporting reports table
    c.execute('''
        CREATE TABLE IF NOT EXISTS reporting_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id INTEGER,
            link TEXT,
            description TEXT,
            notified INTEGER DEFAULT 0,
            UNIQUE(team_id, link)
        )
    ''')

    # Reporting report milestones table
    c.execute('''
        CREATE TABLE IF NOT EXISTS reporting_report_milestones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id INTEGER,
            milestone INTEGER,
            notified INTEGER DEFAULT 0,
            UNIQUE(team_id, milestone)
        )
    ''')

    # Reporting CVEs table
    c.execute('''
        CREATE TABLE IF NOT EXISTS reporting_cves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id INTEGER,
            link TEXT,
            description TEXT,
            notified INTEGER DEFAULT 0,
            UNIQUE(team_id, link)
        )
    ''')

    # Conference submissions table
    c.execute('''
        CREATE TABLE IF NOT EXISTS submissions_conference (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id INTEGER,
            venue TEXT,
            title TEXT,
            notified INTEGER DEFAULT 0,
            UNIQUE(team_id, venue, title)
        )
    ''')

    # Paper submissions table
    c.execute('''
        CREATE TABLE IF NOT EXISTS submissions_paper (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id INTEGER,
            venue TEXT,
            title TEXT,
            notified INTEGER DEFAULT 0,
            UNIQUE(team_id, venue, title)
        )
    ''')

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
