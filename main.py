from app.api import create_app
from app.bootstrap import build_context

ctx = build_context()
app = create_app(ctx.store, ctx.clock, ctx.auth, ctx.guard)
