"""确定性时钟抽象。

校验逻辑只依赖 :meth:`Clock.now`，测试可注入偏移时钟模拟校验端时钟偏移，
临界判定（过期/未来签发）因此完全确定、可复现。
"""
from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    def now(self) -> float:
        """返回当前 Unix 时间（秒）。"""
        ...


class SystemClock:
    """墙钟。"""

    def now(self) -> float:
        return time.time()


class OffsetClock:
    """带固定偏移的时钟，``now = 基准墙钟 + offset``，用于模拟时钟偏移。"""

    def __init__(self, offset_seconds: float = 0.0) -> None:
        self._offset = offset_seconds

    def now(self) -> float:
        return time.time() + self._offset

    def set_offset(self, offset_seconds: float) -> None:
        self._offset = offset_seconds
