import argparse
import sqlite3
import sys
from typing import List, Tuple


def get_tables(conn: sqlite3.Connection) -> List[str]:
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
    return [row[0] for row in cur.fetchall()]


def get_columns(conn: sqlite3.Connection, table: str) -> List[str]:
    cur = conn.execute(f"PRAGMA table_info(`{table}`);")
    return [r[1] for r in cur.fetchall()]


def print_sample_rows(conn: sqlite3.Connection, table: str, limit: int = 5) -> None:
    try:
        cols = get_columns(conn, table)
        cur = conn.execute(f"SELECT * FROM `{table}` LIMIT ?", (limit,))
        rows = cur.fetchall()
        print(f"\nTable: {table} ({len(cols)} columns)")
        if cols:
            print(' | '.join(cols))
            for r in rows:
                print(' | '.join(str(x) for x in r))
        else:
            print("(no column info)")
    except sqlite3.DatabaseError as e:
        print(f"Error reading table {table}: {e}")


def main():
    p = argparse.ArgumentParser(description='Inspect an SQLite database used by the app')
    p.add_argument('--db', '-d', default='instance/database.db', help='Path to sqlite database')
    p.add_argument('--limit', '-n', type=int, default=5, help='Number of sample rows per table')
    args = p.parse_args()

    try:
        conn = sqlite3.connect(args.db)
    except sqlite3.Error as e:
        print(f"Failed to connect to database '{args.db}': {e}")
        sys.exit(2)

    try:
        tables = get_tables(conn)
        if not tables:
            print(f"No tables found in {args.db}")
        else:
            print(f"Found {len(tables)} tables: {', '.join(tables)}")
            for t in tables:
                print_sample_rows(conn, t, args.limit)
    finally:
        conn.close()


if __name__ == '__main__':
    main()
