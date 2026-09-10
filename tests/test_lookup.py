import pytest
import lookup


def test_classify_target_ipv4():
    assert lookup.classify_target("8.8.8.8") == "ip"


def test_classify_target_ipv6():
    assert lookup.classify_target("2001:4860:4860::8888") == "ip"


def test_classify_target_domain():
    assert lookup.classify_target("example.com") == "domain"


def test_classify_target_domain_with_subdomain():
    assert lookup.classify_target("mail.example.co.uk") == "domain"


def test_query_rdap_whois_uses_rdap_when_available(monkeypatch):
    monkeypatch.setattr(lookup.whoisit, "bootstrap", lambda: None)
    monkeypatch.setattr(
        lookup.whoisit, "domain",
        lambda t: {"name": t, "links": [{"href": "https://rdap.apnic.net/domain/example.com"}]},
    )
    result = lookup.query_rdap_whois("example.com")
    assert result["type"] == "domain"
    assert result["source"] == "RDAP（IANA bootstrap → rdap.apnic.net）"
    assert result["data"]["name"] == "example.com"
    assert "queried_at" in result


def test_query_rdap_whois_falls_back_to_whois_on_unsupported_tld(monkeypatch):
    monkeypatch.setattr(lookup.whoisit, "bootstrap", lambda: None)

    def raise_unsupported(t):
        raise lookup.whoisit_errors.UnsupportedError("no rdap for tld")

    monkeypatch.setattr(lookup.whoisit, "domain", raise_unsupported)
    monkeypatch.setattr(
        lookup.whois, "whois",
        lambda t: {"domain_name": t.upper(), "name_servers": ["ns1.example"]},
    )
    result = lookup.query_rdap_whois("example.oldtld")
    assert result["source"] == "WHOIS 備援（TCP 43）"
    assert result["data"]["domain_name"] == "EXAMPLE.OLDTLD"


def test_query_rdap_whois_raises_when_both_fail(monkeypatch):
    monkeypatch.setattr(lookup.whoisit, "bootstrap", lambda: None)

    def raise_query_error(t):
        raise lookup.whoisit_errors.QueryError("rdap down")

    monkeypatch.setattr(lookup.whoisit, "ip", raise_query_error)

    def raise_whois_error(t):
        raise Exception("whois server unreachable")

    monkeypatch.setattr(lookup.whois, "whois", raise_whois_error)
    with pytest.raises(lookup.LookupFailedError):
        lookup.query_rdap_whois("1.2.3.4")


def test_query_rdap_whois_falls_back_to_whois_for_ip_target(monkeypatch):
    monkeypatch.setattr(lookup.whoisit, "bootstrap", lambda: None)

    def raise_query_error(t):
        raise lookup.whoisit_errors.QueryError("rdap down")

    monkeypatch.setattr(lookup.whoisit, "ip", raise_query_error)
    monkeypatch.setattr(
        lookup.whois, "whois",
        lambda t: {"netname": "EXAMPLE-NET", "cidr": "1.2.3.0/24"},
    )
    result = lookup.query_rdap_whois("1.2.3.4")
    assert result["source"] == "WHOIS 備援（TCP 43）"
    assert result["data"]["netname"] == "EXAMPLE-NET"
