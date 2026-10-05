from cryptoh.mitigate.docker_policy import validate as v_docker
from cryptoh.mitigate.iptables import validate as v_ipt
from cryptoh.mitigate.k8s_networkpolicy import validate as v_k8s
from cryptoh.mitigate.nginx_config import validate as v_ngx


def test_iptables_accepts_drop():
    assert v_ipt("iptables -A INPUT -s 10.0.0.14 -j DROP")["valid"] is True


def test_iptables_rejects_flush():
    assert v_ipt("iptables -F")["valid"] is False


def test_nginx_accepts_ratelimit():
    assert v_ngx("limit_req_zone $binary_remote_addr zone=cryptoh:10m rate=5r/s;")["valid"] is True


def test_docker_policy_shape():
    r = v_docker('{"action": "isolate", "container": "web"}')
    assert r["valid"] is True


def test_k8s_policy_shape():
    doc = "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nspec:\n  podSelector: {}\n"
    assert v_k8s(doc)["valid"] is True
