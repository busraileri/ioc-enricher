from ioc_enricher.parser import classify, is_public_ip, parse_iocs, refang

MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_refang_url():
    assert refang("hxxps://example[.]com/a") == "https://example.com/a"


def test_classify_hashes():
    assert classify(MD5) == ("md5", MD5)
    assert classify(SHA1) == ("sha1", SHA1)
    assert classify(SHA256.upper()) == ("sha256", SHA256)


def test_classify_ip_domain_url():
    assert classify("8.8.8.8") == ("ip", "8.8.8.8")
    assert classify("Example[.]ORG") == ("domain", "example.org")
    assert classify("hxxp://example[.]com")[0] == "url"


def test_unknown():
    assert classify("not-an-ioc")[0] == "unknown"


def test_private_ip():
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("192.168.1.10") is False
    assert is_public_ip("127.0.0.1") is False


def test_parse_iocs_dedupe_and_skip():
    lines = ["# comment", "", "8.8.8.8", "8.8.8.8", "10.0.0.5", "???"]
    accepted, skipped = parse_iocs(lines)
    assert accepted == [{"kind": "ip", "value": "8.8.8.8"}]
    assert len(skipped) == 2
