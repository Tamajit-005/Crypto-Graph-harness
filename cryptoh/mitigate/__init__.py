"""Mitigation validators and Jinja2 template rendering."""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from cryptoh.mitigate.docker_policy import validate as validate_docker
from cryptoh.mitigate.iptables import has_unresolved_placeholder
from cryptoh.mitigate.iptables import validate as validate_iptables
from cryptoh.mitigate.k8s_networkpolicy import validate as validate_k8s
from cryptoh.mitigate.nginx_config import validate as validate_nginx

_env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"), autoescape=False)

_VALIDATORS = {
    "iptables": validate_iptables,
    "docker": validate_docker,
    "k8s": validate_k8s,
    "nginx": validate_nginx,
}


def render(template_name: str, **vars: str) -> str:
    """Render a mitigation template by name with the given variables."""
    return _env.get_template(template_name).render(**vars)


def validate_mitigation(kind: str, script: str) -> dict:
    """Validate a whole mitigation script using the validator for its type.

    Picks the right validator instead of assuming iptables, and rejects scripts
    that still contain template placeholders. Never raises.
    """
    if not isinstance(script, str) or not script.strip():
        return {"valid": False, "reason": "empty script"}
    if has_unresolved_placeholder(script):
        return {"valid": False, "reason": "unresolved placeholder in script"}
    key = (kind or "").strip().lower()
    if key in {"docker", "k8s", "nginx", "iptables"}:
        validator = _VALIDATORS[key]
    elif "location" in script or "limit_req" in script:
        validator = validate_nginx
    elif "NetworkPolicy" in script:
        validator = validate_k8s
    elif script.strip().startswith("{"):
        validator = validate_docker
    else:
        validator = validate_iptables
    body = script
    if key == "iptables":
        lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
        if not lines:
            return {"valid": False, "reason": "empty script"}
        results = [validate_iptables(ln) for ln in lines]
        bad = [r["reason"] for r in results if not r["valid"]]
        if bad:
            return {"valid": False, "reason": f"line rejected: {bad[0]}"}
        return {"valid": True, "reason": "ok"}
    return validator(body)


__all__ = [
    "render",
    "validate_docker",
    "validate_iptables",
    "validate_k8s",
    "validate_mitigation",
    "validate_nginx",
]
