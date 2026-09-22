"""本地运行入口: ``uv run uvicorn main:app``。"""
from auth.app import create_app

app = create_app()
