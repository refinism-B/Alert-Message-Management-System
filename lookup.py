import ipaddress
from typing import Literal


def classify_target(value: str) -> Literal["ip", "domain"]:
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        return "domain"
