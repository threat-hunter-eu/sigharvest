"""Quote artifacts retain original matching behavior and expose structural risk."""

import pytest
import yaml

from sigharvest.quality import classify
from sigharvest.quality_quotes import from_raw, quote_artifacts
from tests.test_effective_documents import workspace as workspace_fixture

workspace = workspace_fixture
RAW = """title: Uncommon DLL Load
logsource: {product: windows, category: image_load}
detection:
  selection: {ImageLoaded|endswith: '\\RstrtMgr.dll'}
  filter_main:
    Image|startswith:
      - C:\\Windows\\System32\\'
  condition: selection and not filter_main
level: high
"""


@pytest.mark.parametrize("value", ["C:\\Windows\\", '"C:\\Windows\\"', "O'Reilly", 'cmd /c "thing"', 'echo "hello"'])
def test_legitimate_literals(value):
    assert quote_artifacts({"detection": {"selection": {"Image": value}, "condition": "selection"}}) == {}


def test_deliberate_yaml_quoted_suffix_and_regex_are_not_damage():
    raw = RAW.replace("C:\\Windows\\System32\\'", "'.dll\"'")
    assert from_raw(raw) == {}
    assert "quote_artifact" not in classify(yaml.safe_load(raw), [], raw=raw)
    assert from_raw(RAW.replace("Image|startswith", "Image|re")) == {}


@pytest.mark.parametrize("field", ["NewValue|endswith", "process.cmd_line|contains", "Details|endswith", "ImagePath|contains"])
def test_command_bearing_fields_allow_closing_argument_quote(field):
    assert quote_artifacts({"detection": {"filter": {field: '\\Update\\OneDriveSetup.exe"'}, "condition": "filter"}}) == {}
