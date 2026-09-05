import pytest

from vulnops.sbom.parser import SBOMParser


def test_spdx_component_preserves_purl_and_raw_version():
    bom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "example",
        "documentNamespace": "https://example.com/spdx/1",
        "creationInfo": {"created": "2026-09-05T10:00:00Z", "creators": ["Tool: test"]},
        "packages": [
            {
                "name": "urllib3",
                "SPDXID": "SPDXRef-Package-urllib3",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "verificationCode": "NOASSERTION",
                "versionInfo": "1.26.18",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:pypi/urllib3@1.26.18",
                    }
                ],
            },
            {
                "name": "openssl",
                "SPDXID": "SPDXRef-Package-openssl",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "verificationCode": "NOASSERTION",
                "versionInfo": "3.0.2",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:deb/debian/openssl@3.0.2",
                    }
                ],
            },
        ],
    }
    parser = SBOMParser()
    parsed = parser.parse(bom)
    assert len(parsed.components) == 2
    c0 = parsed.components[0]
    assert c0.purl == "pkg:pypi/urllib3@1.26.18"
    assert c0.raw_version == "1.26.18"
    assert c0.raw_name == "urllib3"

    c1 = parsed.components[1]
    assert c1.purl == "pkg:deb/debian/openssl@3.0.2"
    assert c1.raw_version == "3.0.2"


def test_spdx_without_purl_still_captured():
    bom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "doc",
        "documentNamespace": "https://example.com/spdx/2",
        "creationInfo": {"created": "2026-09-05T10:00:00Z", "creators": ["Tool: test"]},
        "packages": [
            {
                "name": "left-pad",
                "SPDXID": "SPDXRef-Package-leftpad",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "verificationCode": "NOASSERTION",
                "versionInfo": "1.3.0",
            }
        ],
    }
    parser = SBOMParser()
    parsed = parser.parse(bom)
    assert len(parsed.components) == 1
    assert parsed.components[0].raw_name == "left-pad"
    assert parsed.components[0].purl is None


def test_spdx_malformed_raises():
    parser = SBOMParser()
    with pytest.raises(ValueError):
        parser.parse({"spdxVersion": "SPDX-2.3"})  # missing required fields
