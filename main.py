"""Local proxy re-encryption service entry point.

Run with::

    uv run uvicorn main:app --reload

The SQLite database path is controlled by ``PRE_DB_PATH`` and defaults to
``pre_data.db`` in the working directory.
"""

from pre.api import app

__all__ = ["app"]
