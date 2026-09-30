import pytest
import io
from app.connectors.openvas import OpenVASConnector


def test_openvas_csv_realistic_headers():
    """
    Regression test using realistic OpenVAS / Greenbone CSV export headers:
    IP,Hostname,Port,Port Protocol,CVSS,Severity,Solution Type,NVT Name,Summary,Specific Result,NVT OID,CVEs,Task Name,Vulnerability Insight,Impact,Affected Software/OS,Solution,Vulnerability Method,References
    Asserts:
    1. CVE extraction splits comma-separated CVEs, strips whitespace, and takes the first valid CVE-YYYY-NNNNN match.
    2. 'NOCVE', 'NONE', and empty CVEs result in None.
    3. Finding name is properly extracted from 'NVT Name'.
    4. Asset identifier is properly extracted from Hostname/IP.
    5. Port is properly parsed from e.g. 443/tcp.
    """
    connector = OpenVASConnector()

    realistic_csv = (
        "IP,Hostname,Port,Port Protocol,CVSS,Severity,Solution Type,NVT Name,Summary,Specific Result,NVT OID,CVEs,Task Name,Vulnerability Insight,Impact,Affected Software/OS,Solution,Vulnerability Method,References\n"
        '192.168.1.50,db-srv-prod-01,443/tcp,tcp,7.5,High,Mitigation,SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection,The remote service accepts connections encrypted using TLSv1.0.,"Protocol TLSv1.0 is enabled",1.3.6.1.4.1.25623.1.0.108031,"CVE-2011-3389,CVE-2015-2808",Weekly Scan,TLS 1.0 BEAST attack,Attacker can decrypt traffic,OpenSSL,Disable TLS 1.0,Remote check,URL:https://openssl.org\n'
        '192.168.1.51,app-srv-prod-02,8080/tcp,tcp,9.8,Critical,Workaround,Apache Log4j Remote Code Execution,The remote server is vulnerable to RCE.,JNDI injection,1.3.6.1.4.1.25623.1.0.147205,CVE-2021-44228,Weekly Scan,Log4Shell JNDI injection,System takeover,Log4j,Update to 2.15+,Remote check,URL:https://logging.apache.org\n'
        '192.168.1.52,web-gw-01,80/tcp,tcp,0.0,Log,None,HTTP Security Headers Missing,Missing security headers.,Missing X-Frame-Options,1.3.6.1.4.1.25623.1.0.108714,NOCVE,Weekly Scan,Clickjacking risk,Info disclosure,Nginx,Add headers,Remote check,URL:https://owasp.org\n'
        '192.168.1.53,auth-node-03,22/tcp,tcp,5.3,Medium,Mitigation,OpenSSH Deprecated Cipher Suites,The SSH server accepts deprecated ciphers.,CBC ciphers active,1.3.6.1.4.1.25623.1.0.105123,NONE,Weekly Scan,Cipher attacks,Traffic sniffing,OpenSSH,Disable CBC,Remote check,URL:https://openssh.com\n'
        '192.168.1.54,cache-redis-01,6379/tcp,tcp,7.0,High,VendorFix,Redis Unauthenticated Access,Redis database accessible without auth.,Auth not required,1.3.6.1.4.1.25623.1.0.103456,,Weekly Scan,Unauth access,Data leakage,Redis,Require auth,Remote check,URL:https://redis.io\n'
        '192.168.1.55,vpn-gateway,443/tcp,tcp,8.6,High,VendorFix,Citrix NetScaler Gateway Information Disclosure,Sensitive data exposed in memory.,Buffer overread,1.3.6.1.4.1.25623.1.0.149999,"NOCVE, CVE-2023-4966",Weekly Scan,Citrix Bleed,Session hijacking,NetScaler,Apply patch,Remote check,URL:https://citrix.com\n'
    )

    result = connector.parse(realistic_csv.encode("utf-8"), filename="openvas_export.csv")
    findings = result["findings"]
    assert result["skipped"] == 0
    assert len(findings) == 6

    # Row 1: Comma-separated CVEs ("CVE-2011-3389,CVE-2015-2808") -> first valid CVE taken
    f1 = findings[0]
    assert f1["cve_id"] == "CVE-2011-3389"
    assert f1["name"] == "SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection"
    assert f1["asset_id"] == "db-srv-prod-01"
    assert f1["port"] == 443
    assert f1["cvss"] == 7.5
    assert f1["severity"] == "High"

    # Row 2: Single valid CVE
    f2 = findings[1]
    assert f2["cve_id"] == "CVE-2021-44228"
    assert f2["name"] == "Apache Log4j Remote Code Execution"
    assert f2["asset_id"] == "app-srv-prod-02"
    assert f2["port"] == 8080
    assert f2["cvss"] == 9.8
    assert f2["severity"] == "Critical"

    # Row 3: 'NOCVE' -> None
    f3 = findings[2]
    assert f3["cve_id"] is None
    assert f3["name"] == "HTTP Security Headers Missing"
    assert f3["asset_id"] == "web-gw-01"
    assert f3["severity"] == "Log"

    # Row 4: 'NONE' -> None
    f4 = findings[3]
    assert f4["cve_id"] is None
    assert f4["name"] == "OpenSSH Deprecated Cipher Suites"
    assert f4["asset_id"] == "auth-node-03"

    # Row 5: empty CVEs -> None
    f5 = findings[4]
    assert f5["cve_id"] is None
    assert f5["name"] == "Redis Unauthenticated Access"
    assert f5["asset_id"] == "cache-redis-01"

    # Row 6: 'NOCVE, CVE-2023-4966' -> skips NOCVE, extracts CVE-2023-4966
    f6 = findings[5]
    assert f6["cve_id"] == "CVE-2023-4966"
    assert f6["name"] == "Citrix NetScaler Gateway Information Disclosure"
    assert f6["asset_id"] == "vpn-gateway"


def test_openvas_csv_fallback_chain_intact():
    """
    Asserts that the existing fallback chain remains fully functional:
    - row.get('CVE') or row.get('cve_id') when 'CVEs' is absent.
    - row.get('Name') or row.get('name') when 'NVT Name' is absent.
    - row.get('Host') or row.get('asset_id') or row.get('IP') fallback.
    """
    connector = OpenVASConnector()

    # Legacy OpenVAS CSV format with 'Host', 'Port', 'CVSS', 'Severity', 'CVE', 'Name'
    legacy_csv_1 = (
        "Host,Port,CVSS,Severity,CVE,Name\n"
        "10.0.0.1,22,7.5,High,CVE-2021-34527,PrintNightmare Vulnerability\n"
        "10.0.0.2,443,9.8,Critical,NOCVE,Generic Misconfiguration\n"
    )
    res1 = connector.parse(legacy_csv_1.encode("utf-8"), filename="scan.csv")
    assert len(res1["findings"]) == 2
    assert res1["findings"][0]["cve_id"] == "CVE-2021-34527"
    assert res1["findings"][0]["name"] == "PrintNightmare Vulnerability"
    assert res1["findings"][0]["asset_id"] == "10.0.0.1"
    assert res1["findings"][1]["cve_id"] is None
    assert res1["findings"][1]["name"] == "Generic Misconfiguration"

    # Alternative lower-case / snake_case format: 'asset_id,port,cvss,severity,cve_id,name'
    legacy_csv_2 = (
        "asset_id,port,cvss,severity,cve_id,name\n"
        "srv-backend-01,80,5.0,Medium,CVE-2022-22965,Spring4Shell Vulnerability\n"
    )
    res2 = connector.parse(legacy_csv_2.encode("utf-8"), filename="alt_scan.csv")
    assert len(res2["findings"]) == 1
    assert res2["findings"][0]["cve_id"] == "CVE-2022-22965"
    assert res2["findings"][0]["name"] == "Spring4Shell Vulnerability"
    assert res2["findings"][0]["asset_id"] == "srv-backend-01"


def test_extract_cve_unit_helper():
    """Unit tests for OpenVASConnector._extract_cve helper covering various inputs."""
    extract = OpenVASConnector._extract_cve

    # Standard valid
    assert extract("CVE-2021-44228") == "CVE-2021-44228"
    assert extract("cve-2021-44228") == "CVE-2021-44228"

    # Comma-separated (plural)
    assert extract("CVE-2011-3389,CVE-2015-2808") == "CVE-2011-3389"
    assert extract("  CVE-2011-3389 , CVE-2015-2808 ") == "CVE-2011-3389"

    # Prefix with invalid/NOCVE
    assert extract("NOCVE, CVE-2024-3400") == "CVE-2024-3400"
    assert extract("UNKNOWN, CVE-2024-3400") == "CVE-2024-3400"

    # Null / empty / negative representations
    assert extract("NOCVE") is None
    assert extract("nocve") is None
    assert extract("NONE") is None
    assert extract("none") is None
    assert extract("N/A") is None
    assert extract("") is None
    assert extract("   ") is None
    assert extract(None) is None
    assert extract("NON-CVE-STRING") is None
