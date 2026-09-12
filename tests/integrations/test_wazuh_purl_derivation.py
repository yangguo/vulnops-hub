"""Unit tests for Wazuh syscollector -> Package URL derivation."""

from vulnops.integrations.wazuh_purl import derive_purl_from_wazuh_package, enrich_wazuh_package

_DEBIAN_AGENT = {"os": {"name": "Debian GNU/Linux", "version": "12"}}
_UBUNTU_AGENT = {"os": {"name": "Ubuntu", "version": "22.04"}}


def test_derives_deb_purl_when_agent_os_is_debian():
    package = {
        "name": "openssl",
        "version": "3.0.2",
        "format": "deb",
        "architecture": "x86_64",
    }
    result = derive_purl_from_wazuh_package(package, agent=_DEBIAN_AGENT)
    assert result.status == "derived"
    assert result.purl == "pkg:deb/debian/openssl@3.0.2?arch=x86_64"


def test_deb_ignores_package_vendor_without_agent_os():
    result = derive_purl_from_wazuh_package(
        {
            "name": "curl",
            "version": "7.81.0",
            "format": "deb",
            "vendor": "Ubuntu",
        }
    )
    assert result.status == "skipped"
    assert result.reason == "deb_distro_unknown"


def test_deb_ubuntu_namespace_from_agent_os():
    result = derive_purl_from_wazuh_package(
        {"name": "curl", "version": "7.81.0", "format": "deb"},
        agent=_UBUNTU_AGENT,
    )
    assert result.purl == "pkg:deb/ubuntu/curl@7.81.0"


def test_skips_deb_without_agent_distro():
    result = derive_purl_from_wazuh_package(
        {"name": "openssl", "version": "3.0.2", "format": "deb", "architecture": "x86_64"}
    )
    assert result.status == "skipped"
    assert result.reason == "deb_distro_unknown"


def test_derives_apk_purl():
    result = derive_purl_from_wazuh_package(
        {"name": "busybox", "version": "1.36.1", "format": "apk"}
    )
    assert result.status == "derived"
    assert result.purl == "pkg:apk/alpine/busybox@1.36.1"


def test_derives_rpm_when_vendor_maps_to_namespace():
    result = derive_purl_from_wazuh_package(
        {
            "name": "curl",
            "version": "7.0.1-1.el9",
            "format": "rpm",
            "vendor": "Fedora Project",
        }
    )
    assert result.status == "derived"
    assert result.purl == "pkg:rpm/fedora/curl@7.0.1-1.el9"


def test_opensuse_vendor_maps_to_opensuse_not_suse():
    result = derive_purl_from_wazuh_package(
        {
            "name": "curl",
            "version": "8.0.1",
            "format": "rpm",
            "vendor": "openSUSE Project",
        }
    )
    assert result.status == "derived"
    assert result.purl == "pkg:rpm/opensuse/curl@8.0.1"


def test_skips_rpm_without_recognizable_vendor():
    result = derive_purl_from_wazuh_package({"name": "curl", "version": "1.0", "format": "rpm"})
    assert result.status == "skipped"
    assert result.reason == "rpm_namespace_unknown"


def test_skips_missing_format():
    result = derive_purl_from_wazuh_package({"name": "openssl", "version": "3.0.2"})
    assert result.status == "skipped"
    assert result.reason == "missing_format"


def test_skips_unsupported_format():
    result = derive_purl_from_wazuh_package({"name": "foo", "version": "1", "format": "snap"})
    assert result.status == "skipped"
    assert "unsupported_format" in (result.reason or "")


def test_preserves_existing_purl_without_rewriting():
    package = {"name": "x", "version": "1", "purl": "pkg:deb/debian/x@1.0"}
    result = derive_purl_from_wazuh_package(package)
    assert result.status == "present"
    assert result.purl == "pkg:deb/debian/x@1.0"
    enriched, meta = enrich_wazuh_package(package)
    assert meta.status == "present"
    assert enriched["purl"] == package["purl"]


def test_derivation_is_stable_and_does_not_add_spurious_fields():
    package = {"name": "openssl", "version": "3.0.2", "format": "deb"}
    first = derive_purl_from_wazuh_package(package, agent=_DEBIAN_AGENT)
    second = derive_purl_from_wazuh_package(package, agent=_DEBIAN_AGENT)
    assert first == second
    enriched, meta = enrich_wazuh_package(package, agent=_DEBIAN_AGENT)
    assert set(enriched.keys()) == set(package.keys()) | {"purl"}
    assert meta.status == "derived"
