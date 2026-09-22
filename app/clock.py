"""确定性时钟。

所有令牌签发与校验都通过 Clock 取当前时间，测试中可手动推进/偏移，
避免依赖真实墙钟导致临界用例出现随机结论。
"""
from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class Clock:
    """可手动控制的时钟；时间为 epoch 秒浮点值。

    - instant 为 None 时跟随真实墙钟；
    - offset 表示"校验方时钟相对权威时钟的偏移"，仅影响 now()，
      用于确定性地模拟时钟偏移临界场景；
    - advance 只推进受控时钟（instant 非 None）。
    """

    instant: float | None = None
    offset: float = 0.0

    def now(self) -> float:
        if self.instant is None:
            return time.time() + self.offset
        return self.instant + self.offset

    def advance(self, seconds: float) -> None:
        if self.instant is None:
            self.instant = time.time()
        self.instant += seconds

    def set_offset(self, seconds: float) -> None:
        self.offset = seconds

    @classmethod
    def real(cls) -> "Clock":
        return cls(instant=None, offset=0.0)
