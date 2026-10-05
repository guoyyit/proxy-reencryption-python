"""Development entrypoint: `uv run uvicorn main:app`."""

from app.api import app

__all__ = ["app"]

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
