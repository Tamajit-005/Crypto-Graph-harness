"""Mitigation validators and Jinja2 template rendering."""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from cryptoh.mitigate.docker_policy import validate as validate_docker
from cryptoh.mitigate.iptables import validate as validate_iptables
from cryptoh.mitigate.k8s_networkpolicy import validate as validate_k8s
from cryptoh.mitigate.nginx_config import validate as validate_nginx

_env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"), autoescape=False)


def render(template_name: str, **vars: str) -> str:
    """Render a mitigation template by name with the given variables."""
    return _env.get_template(template_name).render(**vars)


__all__ = [
    "render",
    "validate_docker",
    "validate_iptables",
    "validate_k8s",
    "validate_nginx",
]
