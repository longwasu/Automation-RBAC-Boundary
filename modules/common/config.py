from dataclasses import dataclass, field
from typing import List
import yaml

@dataclass
class UserCred:
    username: str
    password: str
    roles: List[str] = field(default_factory=list)
@dataclass
class Config:
    base_url: str
    verify_tls: bool
    users: List[UserCred]
    def users_low_to_high(self) -> List[UserCred]:
        return self.users

def load_config(path: str) -> Config:
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    return Config(
        base_url=raw["base_url"],
        verify_tls=bool(raw.get("verify_tls", False)),
        users=[UserCred(u["username"], u.get("password", ""), list(u.get("roles", [])))
               for u in raw.get("users", [])],
    )