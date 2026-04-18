"""Payload data model."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Payload:
    name: str
    language: str
    type: str       # reverse | bind | webshell | encoded
    content: str
    lhost: str = ""
    lport: int = 0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "language": self.language,
            "type": self.type,
            "lhost": self.lhost,
            "lport": self.lport,
            "content": self.content,
        }
