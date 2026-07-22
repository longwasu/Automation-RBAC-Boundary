from dataclasses import dataclass, field
from typing import List, Literal, Optional
import requests
Verdict = Literal["allow", "deny"]

@dataclass
class Session:
    """Produced by task-B. An authenticated HTTP session for one user."""
    http: requests.Session
    username: str
    roles: List[str]

Matrix = dict
@dataclass
class Probe:
    group: str
    method: str                     # "GET" | "PUT" | "POST" | "DELETE"
    path: str                       # "/agents", "/agents/000/ar/isolate", ...
    body: Optional[dict] = None

@dataclass
class ProbeResult:
    username: str
    roles: List[str]
    group: str
    method: str
    path: str
    status: int
    actual_allow: bool
    matrix_expected: bool
    invariant_verdict: Optional[Verdict] = None
    ok: bool = False
    signals: List[int] = field(default_factory=list)