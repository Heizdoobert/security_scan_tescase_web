import pytest
from websec_test.discovery.crawler import PlaywrightCrawler

def test_crawler_internal_ip():
    crawler = PlaywrightCrawler(target_url="http://example.com")
    assert crawler._is_internal_ip("127.0.0.1") is True
    assert crawler._is_internal_ip("localhost") is True
    assert crawler._is_internal_ip("169.254.169.254") is True
    assert crawler._is_internal_ip("example.com") is False

def test_crawler_internal_ip_allowed_for_localhost():
    crawler = PlaywrightCrawler(target_url="http://localhost:8080")
    # If the target is localhost, then localhost and 127.0.0.1 should not be blocked as SSRF
    assert crawler._is_internal_ip("127.0.0.1") is False
    assert crawler._is_internal_ip("localhost") is False

def test_crawler_fallback():
    # If Playwright is installed, it will try to launch and either fail or succeed. 
    # Just testing initialization and simple method.
    crawler = PlaywrightCrawler(target_url="http://example.com")
    assert crawler.target_url == "http://example.com"
