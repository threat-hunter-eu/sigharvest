from sigharvest.semantic import semantic_hash

A = """title: a
id: 0a5c2b1e-0000-4000-8000-000000000001
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\\\\whoami.exe'
    CommandLine|contains: ['/all', '/priv']
  filter:
    User: SYSTEM
  condition: selection and not filter
"""

B = """title: completely different metadata
id: not-a-uuid
tags: [bad tag]
logsource: {category: process_creation, product: windows}
detection:
  sel_img:
    Image: '*\\\\WHOAMI.exe'
  sel_cli:
    - CommandLine: '*/priv*'
    - CommandLine: '*/all*'
  f:
    User: system
  condition: (sel_cli and sel_img) and not f
"""


def test_same_detection_written_differently() -> None:
    assert semantic_hash(A) is not None
    assert semantic_hash(A) == semantic_hash(B)


def test_one_of_pattern_equals_explicit_or() -> None:
    x = A.replace("condition: selection and not filter", "condition: 1 of sel* and not filter")
    assert semantic_hash(x) == semantic_hash(A)


def test_real_changes_change_the_hash() -> None:
    assert semantic_hash(A.replace("/priv", "/groups")) != semantic_hash(A)
    assert semantic_hash(A.replace("and not filter", "and filter")) != semantic_hash(A)
    assert semantic_hash(A.replace("process_creation", "image_load")) != semantic_hash(A)
    assert semantic_hash(A.replace("Image|endswith", "Image|startswith")) != semantic_hash(A)


def test_cased_values_keep_case() -> None:
    a = A.replace("CommandLine|contains", "CommandLine|cased|contains")
    b = a.replace("/all", "/ALL")
    assert semantic_hash(a) != semantic_hash(b)


def test_unparseable_rule_has_no_hash() -> None:
    assert semantic_hash("title: x\nlogsource: {}\ndetection:\n  condition: nothing\n") is None
