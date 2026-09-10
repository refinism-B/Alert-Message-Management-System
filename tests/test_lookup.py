import lookup


def test_classify_target_ipv4():
    assert lookup.classify_target("8.8.8.8") == "ip"


def test_classify_target_ipv6():
    assert lookup.classify_target("2001:4860:4860::8888") == "ip"


def test_classify_target_domain():
    assert lookup.classify_target("example.com") == "domain"


def test_classify_target_domain_with_subdomain():
    assert lookup.classify_target("mail.example.co.uk") == "domain"
