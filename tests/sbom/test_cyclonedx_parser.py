import pytest

from vulnops.sbom.parser import ParsedSBOM, SBOMParser


def test_cyclonedx_component_preserves_purl_and_raw_version():
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "myapp",
                "version": "1.0.0",
                "bom-ref": "myapp@1.0.0",
            }
        },
        "components": [
            {
                "type": "library",
                "name": "urllib3",
                "version": "1.26.18",
                "purl": "pkg:pypi/urllib3@1.26.18",
                "bom-ref": "urllib3@1.26.18",
            },
            {
                "type": "library",
                "name": "openssl",
                "version": "3.0.2",
                "purl": "pkg:deb/debian/openssl@3.0.2?arch=x86_64",
                "cpe": "cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*",
            },
        ],
    }
    parser = SBOMParser()
    parsed: ParsedSBOM = parser.parse(bom)
    assert len(parsed.components) == 2
    c0 = parsed.components[0]
    assert c0.purl == "pkg:pypi/urllib3@1.26.18"
    assert c0.raw_version == "1.26.18"
    assert c0.raw_name == "urllib3"
    assert c0.ecosystem == "pypi"

    c1 = parsed.components[1]
    assert c1.purl == "pkg:deb/debian/openssl@3.0.2?arch=x86_64"
    assert c1.raw_version == "3.0.2"
    # CPE should be preserved as alias, not canonical
    assert c1.cpe == "cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"
    # purl type is deb
    assert c1.ecosystem == "deb"


def test_cyclonedx_parser_preserves_raw_and_normalized():
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {
                "name": "tomcat-catalina",
                "version": "9.0.80",
                "purl": "pkg:maven/org.apache.tomcat/tomcat-catalina@9.0.80",
                "group": "org.apache.tomcat",
            }
        ],
    }
    parser = SBOMParser()
    parsed = parser.parse(bom)
    comp = parsed.components[0]
    # Must retain original
    assert comp.raw_name == "tomcat-catalina"
    assert comp.raw_version == "9.0.80"
    assert comp.purl == "pkg:maven/org.apache.tomcat/tomcat-catalina@9.0.80"
    # normalized name should be group/name or purl-based
    assert comp.normalized_name is not None
    assert "tomcat" in comp.normalized_name


def test_cyclonedx_malformed_raises_validation_error():
    bom = {"not": "cyclonedx"}
    parser = SBOMParser()
    with pytest.raises(ValueError) as exc:
        parser.parse(bom)
    # Should indicate validation issue, not silent success
    msg = str(exc.value).lower()
    assert "invalid" in msg or "cyclone" in msg or "spdx" in msg or "bom" in msg


def test_cyclonedx_without_purl_still_preserves_raw():
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"name": "left-pad", "version": "1.3.0"}],
    }
    parser = SBOMParser()
    parsed = parser.parse(bom)
    c = parsed.components[0]
    assert c.raw_name == "left-pad"
    assert c.raw_version == "1.3.0"
    assert c.purl is None
    assert c.ecosystem is None or c.ecosystem == "generic"
