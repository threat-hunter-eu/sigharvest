"""A `# SPDX-License-Identifier:` header is the rule's own licence: it may narrow the source licence, never widen it."""

from sigharvest.documents import load_documents
from sigharvest.ingest import _version_fields
from sigharvest.licensing import licence_class, narrows, shipped_licence, spdx_expression_licence, spdx_header, stricter

RULE = """title: Example
id: 0b7c2f4e-1111-4222-8333-944455556666
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    Image|endswith: '\\\\x.exe'
  condition: sel
level: low
"""


def _rule_license(text: str) -> str | None:
    docs = [d for d in load_documents(text.encode()) if d.kind]
    assert docs, "fixture must parse as a Sigma rule"
    return _version_fields(docs[0], "c", "l", "r", [], None)["rule_license"]


def test_spdx_header_reads_the_first_comment_line() -> None:
    assert spdx_header("# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0\n" + RULE) == "LicenseRef-PolyForm-Strict-1.0.0"
    assert spdx_header("#SPDX-License-Identifier:   MIT  \n" + RULE) == "MIT"
    assert spdx_header(RULE) is None
    assert spdx_header("description: 'SPDX-License-Identifier: MIT'\n") is None  # only a comment line counts
    assert spdx_header("# SPDX-License-Identifier:\n" + RULE) is None
    # a header far below the top is not a file header
    assert spdx_header("#\n" * 9000 + "# SPDX-License-Identifier: GPL-3.0-only\n") is None


def test_spdx_expressions() -> None:
    assert spdx_expression_licence("MIT OR GPL-3.0-only") == "MIT"
    assert spdx_expression_licence("MIT AND GPL-3.0-only") == "GPL-3.0-only"
    assert spdx_expression_licence("GPL-2.0-or-later WITH Classpath-exception-2.0") == "GPL-2.0-or-later"
    # nested expressions stay whole: restricted, the conservative reading
    assert licence_class(spdx_expression_licence("(MIT OR Apache-2.0) AND CC-BY-NC-4.0")) == "restricted"


def test_stricter_and_narrowing() -> None:
    assert stricter(None, "MIT") == "MIT" and stricter("MIT", None) == "MIT" and stricter(None, None) is None
    assert stricter("MIT", "LicenseRef-PolyForm-Strict-1.0.0") == "LicenseRef-PolyForm-Strict-1.0.0"
    assert stricter("Elastic-2.0", "MIT") == "Elastic-2.0"
    # a header can only narrow: MIT in a GPL repository still ships as GPL
    assert not narrows("MIT", "GPL-3.0-only") and shipped_licence("MIT", "GPL-3.0-only") == "GPL-3.0-only"
    assert shipped_licence("LicenseRef-PolyForm-Strict-1.0.0", "MIT") == "LicenseRef-PolyForm-Strict-1.0.0"


def test_ingest_takes_the_header_as_the_rule_licence() -> None:
    # the relicensing case (a repository switched to a no-redistribution licence by editing file headers)
    assert _rule_license("# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0\n" + RULE) == "LicenseRef-PolyForm-Strict-1.0.0"
    assert _rule_license(RULE) is None
    assert _rule_license(RULE + "license: DRL 1.1\n") == "DRL 1.1"
    # both stated: the stricter one wins
    assert _rule_license("# SPDX-License-Identifier: Elastic-2.0\n" + RULE + "license: MIT\n") == "Elastic-2.0"
    assert _rule_license("# SPDX-License-Identifier: MIT\n" + RULE + "license: Elastic-2.0\n") == "Elastic-2.0"
