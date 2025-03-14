#!/usr/bin/env python3
import sqlite3
import os

# Determine the database path.
# This script assumes it is run from {repo}/.github (or similar) and that the project directory is at ../proj/.
repo_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
db_path = os.path.join(repo_root, "proj", "result.db")

def init_db():
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Table to store teams (each JSON file represents a team)
    c.execute('''
        CREATE TABLE IF NOT EXISTS teams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE
        )
    ''')

    # Table for implementation products
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

    # Table for fuzzing fuzzers
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

    # Table for auditing targets
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

    # Table for reporting reports
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

    # Table for reporting CVEs
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

    # Table for conference submissions
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

    # Table for paper submissions
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

    # Table for accumulated crash milestones (reporting)
    c.execute('''
        CREATE TABLE IF NOT EXISTS reporting_crash_milestones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id INTEGER,
            milestone INTEGER,
            notified INTEGER DEFAULT 0,
            UNIQUE(team_id, milestone)
        )
    ''')

    # Table for report count milestones (reporting)
    c.execute('''
        CREATE TABLE IF NOT EXISTS reporting_report_milestones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id INTEGER,
            milestone INTEGER,
            notified INTEGER DEFAULT 0,
            UNIQUE(team_id, milestone)
        )
    ''')

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()

