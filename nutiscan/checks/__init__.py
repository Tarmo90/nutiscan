"""Check registry and the context handed to every check."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..config import Config
from ..crawling import Endpoint, Page
from ..findings import Finding
from ..http import Client, Response


@dataclass
class Context:
    client: Client
    config: Config
    origin: str
    root: Response
    pages: list[Page]
    endpoints: list[Endpoint]
    log: Callable[[str], None]
    emit: Callable[[Finding], None]
    stop: Callable[[], bool]


def load_checks() -> list[dict]:
    from . import active, exposed, graphql, passive

    return [*passive.CHECKS, *exposed.CHECKS, *active.CHECKS, *graphql.CHECKS]


__all__ = ["Context", "load_checks", "Endpoint", "Page"]
