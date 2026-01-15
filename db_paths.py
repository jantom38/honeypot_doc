import os


def resolve_db_path() -> str:
    """Resolve honeypot DB path independent of current working directory."""
    env_db = os.environ.get('HONEYPOT_DB_PATH')
    if env_db:
        return env_db

    is_docker = os.environ.get('IS_DOCKER', 'false').lower() == 'true'
    if is_docker:
        return '/app/data/honeypot_events.db'

    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, 'data', 'honeypot_events.db')


def resolve_db_uri_readonly() -> str:
    """Return SQLite URI for read-only access."""
    path = resolve_db_path()
    return f"file:{path}?mode=ro"
