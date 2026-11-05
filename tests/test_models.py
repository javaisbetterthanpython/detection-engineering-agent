import json
import re

import pytest
import yaml
from pydantic import ValidationError

from detection_engineering_agent import models
from detection_engineering_agent.models import (
    SOURCETYPE_META,
    Detection,
    Draft,
    Finding,
    Idea,
    IdeasOut,
    Inventory,
    ReviewOut,
    ReviewRound,
    SplOut,
    Tags,
    schema,
)

SYSMON = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"


def test_idea_example_validates(idea):
    assert idea.id == "3f0e6b5a-1d0c-4c6e-9d3e-5b2d6a8c1f11"
    assert idea.stem == "office_app_spawns_encoded_powershell"
    assert idea.severity == "high" and idea.attack_examples == []
    assert idea.log_sources[1].keywords == ["wineventlog", "security", "4688"]


@pytest.mark.parametrize(
    "bad",
    [
        {"mitre_attack_id": ["T1059.001", "1059"]},
        {"id": "../../outside"},
        {"id": "not-a-uuid"},
        {"id": "3f0e6b5a-1d0c-1c6e-9d3e-5b2d6a8c1f11"},  # version 1, not 4
        {"title": "x" * 100},
        {"title": ""},
        {"title": "Обнаружение атаки"},  # no ASCII letter/digit -> empty stem -> ideas/.yml, `_filter` macro
        {"title": "--- ***"},
        {"summary": "y" * 601},
        {"attack_steps": []},
        {"log_sources": []},
        {"log_sources": [{"product": "p", "keywords": [], "fields": []}]},
        {"type": "Hunt"},
        {"severity": "urgent"},
        {"unknown_key": 1},
    ],
)
def test_idea_rejects(idea, bad):
    with pytest.raises(ValidationError):
        Idea.model_validate({**idea.model_dump(), **bad})


def test_idea_empty_stem_rejected_with_reason(idea):
    with pytest.raises(ValidationError, match="stem would be empty"):
        Idea.model_validate({**idea.model_dump(), "title": "Обнаружение атаки"})
    mixed = Idea.model_validate({**idea.model_dump(), "title": "Обнаружение PowerShell"})
    assert mixed.stem == "powershell"


def test_idea_defaults(idea):
    data = idea.model_dump()
    for k in ("severity", "indicators", "sourcetypes", "attack_examples", "max_hits_per_day", "source_url"):
        data.pop(k)
    i = Idea.model_validate(data)
    assert i.severity == "medium" and i.indicators == [] and i.source_url is None


@pytest.mark.parametrize("type_, expected", [("TTP", 5), ("Anomaly", 20), ("Hunting", 100)])
def test_threshold_per_type(idea, type_, expected):
    assert idea.model_copy(update={"type": type_}).threshold == expected
    assert idea.model_copy(update={"type": type_, "max_hits_per_day": 42}).threshold == 42


def test_schema_ideas_out_carries_limits():
    s = schema(IdeasOut)
    ref = s["properties"]["ideas"]["items"]["$ref"]
    props = s["$defs"][ref.rsplit("/", 1)[1]]["properties"]
    assert props["title"]["maxLength"] == 99
    assert props["summary"]["maxLength"] == 600
    assert "LogSource" in s["$defs"]
    assert schema(SplOut)["required"] == ["spl"]


def test_inventory_helpers(inventory):
    assert inventory.index_names() == {"wineventlog", "proxy"}
    assert {SYSMON, "WinEventLog:Security", "squid:access"} <= inventory.sourcetype_names()
    assert inventory.fields_for(SYSMON)["EventCode"] == ["1", "3", "11"]
    assert inventory.fields_for("nope") == {}
    assert inventory.sample_for(SYSMON).startswith("<Event")
    assert inventory.sample_for("nope") is None
    assert inventory.find("wineventlog", SYSMON).count == 912000
    with pytest.raises(KeyError):
        inventory.find("proxy", SYSMON)
    assert inventory.macros == ["sysmon", "security_content_ctime"]


def test_inventory_round_trip(inventory):
    assert Inventory.model_validate_json(inventory.model_dump_json()) == inventory
    with pytest.raises(ValidationError):
        Inventory.model_validate({"fetched_at": "x", "window": "-7d", "extra": 1})


@pytest.mark.parametrize(
    "name, meta",
    [
        (SYSMON, ("Sysmon EventID 1", "Endpoint", "endpoint")),
        ("WinEventLog:Security", ("Windows Event Log Security 4688", "Endpoint", "endpoint")),
        ("WinEventLog:System", ("Windows Event Log", "Endpoint", "endpoint")),
        ("squid:access", ("Nginx Access", "Web Server", "network")),
        ("aws:cloudtrail", ("AWS CloudTrail", "AWS Account", "threat")),
        ("pan:traffic", ("Zeek", "Network", "network")),
    ],
)
def test_sourcetype_meta_first_match(name, meta):
    row = next((r for r in SOURCETYPE_META if re.search(r[0], name, re.I)), None)
    assert row[1:] == meta


def test_sourcetype_meta_domains_in_enum():
    allowed = set(Tags.model_fields["security_domain"].annotation.__args__)
    assert {row[3] for row in SOURCETYPE_META} <= allowed


def test_inference_output_models():
    r = ReviewOut.model_validate(
        {
            "findings": [{"category": "evasion", "severity": "medium", "detail": "d", "fix_hint": "f"}],
            "evasion_events": [{"sourcetype": SYSMON, "raw": "<Event/>", "note": "n"}],
        }
    )
    assert r.findings[0].severity == "medium"
    assert "verdict" not in ReviewOut.model_fields and "verdict" not in Finding.model_fields
    with pytest.raises(ValidationError):
        Finding(category="style", severity="low", detail="d", fix_hint="f")
    with pytest.raises(ValidationError):
        SplOut.model_validate({"spl": "x", "extra": 1})
    rr = ReviewRound(round=1, draft=3, findings=r.findings, evasion_events=r.evasion_events)
    assert ReviewRound.model_validate_json(rr.model_dump_json()) == rr


def test_state_element_models():
    d = Draft(n=1, origin="author", spl="index=a | stats count by Computer", group_fields=["Computer"], fields_used=["Computer"])
    assert Draft.model_validate_json(d.model_dump_json()) == d
    with pytest.raises(ValidationError):
        Draft(n=1, origin="review", spl="x", group_fields=[], fields_used=[])
    s = models.Source(index="i", sourcetype=SYSMON, score=14, data_source="Sysmon EventID 1", asset_type="Endpoint", security_domain="endpoint")
    assert models.Example(sourcetype=s.sourcetype, raw="r", host="dea-abcd1234-0").host.startswith("dea-")


DETECTION = {
    "name": "Office app spawns encoded PowerShell",
    "id": "3f0e6b5a-1d0c-4c6e-9d3e-5b2d6a8c1f11",
    "version": 1,
    "date": "2026-11-04",
    "author": "detection-engineering-agent",
    "status": "experimental",
    "type": "TTP",
    "description": "d",
    "data_source": ["Sysmon EventID 1"],
    "search": "index=wineventlog | stats count by Computer | `office_app_spawns_encoded_powershell_filter`",
    "how_to_implement": "h",
    "known_false_positives": "k",
    "references": ["https://thedfirreport.com/2026/10/30/example/"],
    "drilldown_searches": [
        {"name": "View the detection results for $Computer$", "search": "%original_detection_search% | search Computer=\"$Computer$\"",
         "earliest_offset": "$info_min_time$", "latest_offset": "$info_max_time$"},
    ],
    "rba": {
        "message": "m",
        "risk_objects": [{"field": "Computer", "type": "system", "score": 70}],
        "threat_objects": [{"field": "CommandLine", "type": "command"}],
    },
    "tags": {
        "analytic_story": ["Office app spawns encoded PowerShell"],
        "asset_type": "Endpoint",
        "mitre_attack_id": ["T1059.001"],
        "product": ["Splunk Enterprise", "Splunk Enterprise Security", "Splunk Cloud"],
        "security_domain": "endpoint",
        "throttling": {"fields": ["Computer"], "period": "86400s"},
    },
    "tests": [{"name": "True Positive Test", "attack_data": [{"data": "https://x/a.log", "source": SYSMON, "sourcetype": SYSMON}], "test_type": "unit"}],
}


def test_detection_validates_and_keeps_field_order():
    det = Detection.model_validate(DETECTION)
    assert list(det.model_dump()) == list(DETECTION)
    assert det.model_dump(exclude_none=True) == DETECTION
    hunting = Detection.model_validate({k: v for k, v in DETECTION.items() if k not in ("rba", "drilldown_searches", "tests")} | {"type": "Hunting"})
    assert "rba" not in hunting.model_dump(exclude_none=True)


@pytest.mark.parametrize(
    "bad",
    [
        {"status": "draft"},
        {"x_dea": {}},
        {"tags": {**DETECTION["tags"], "security_domain": "cloud"}},
        {"rba": {**DETECTION["rba"], "threat_objects": [{"field": "f", "type": "hash"}]}},
        {"rba": {**DETECTION["rba"], "risk_objects": [{"field": "f", "type": "host", "score": 1}]}},
        {"rba": {**DETECTION["rba"], "risk_objects": []}},
    ],
)
def test_detection_rejects(bad):
    with pytest.raises(ValidationError):
        Detection.model_validate({**DETECTION, **bad})


# --- 7.5 rendering ------------------------------------------------------------

SPL = (
    'index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\\\powershell.exe"'
    " | stats count by Computer User ParentImage Image CommandLine"
)
DRAFT = Draft(n=1, origin="author", spl=SPL, group_fields=["Computer", "User", "ParentImage", "Image", "CommandLine"],
              fields_used=["CommandLine", "Computer", "EventCode", "Image", "ParentImage", "User"])
SOURCES = [
    models.Source(index="wineventlog", sourcetype=SYSMON, score=14, data_source="Sysmon EventID 1", asset_type="Endpoint", security_domain="endpoint"),
    models.Source(index="winsec", sourcetype="WinEventLog:Security", score=11, data_source="Windows Event Log Security 4688",
                  asset_type="Endpoint", security_domain="endpoint"),
]
FINDINGS = [
    Finding(category="false_positive", severity="medium", detail="Signed vendor add-ins", fix_hint="x"),
    Finding(category="evasion", severity="low", detail="not an fp", fix_hint="y"),
]


def test_from_run_renders_detection(idea, tmp_path):
    det = Detection.from_run(idea, DRAFT, SOURCES, FINDINGS, "experimental", tmp_path)
    assert det.name == idea.title and det.id == idea.id and det.version == 1 and det.status == "experimental"
    assert det.author == "detection-engineering-agent" and det.type == "TTP"
    assert det.description == f"{idea.summary}\n\nDetects: {'; '.join(idea.attack_steps)}"
    assert det.search.startswith("index=wineventlog") and det.search.endswith("| `office_app_spawns_encoded_powershell_filter`")
    assert det.data_source == ["Sysmon EventID 1"]  # only the source whose sourcetype/index the search references
    assert det.how_to_implement.startswith(f"Ingest Windows Sysmon as sourcetype {SYSMON} into index wineventlog. Ingest Windows Security as sourcetype WinEventLog:Security into index winsec. ")
    assert "Fields used: CommandLine, Computer, EventCode, Image, ParentImage, User." in det.how_to_implement
    assert det.known_false_positives == "Admin scripts launched from Office automation in finance. Review findings: Signed vendor add-ins (medium)"
    assert det.references == [idea.source_url]
    assert [o.model_dump() for o in det.rba.risk_objects] == [
        {"field": "Computer", "type": "system", "score": 70}, {"field": "User", "type": "user", "score": 70}]
    assert [(t.field, t.type) for t in det.rba.threat_objects] == [
        ("ParentImage", "parent_process_name"), ("Image", "process_name"), ("CommandLine", "command")]
    assert det.rba.message == "Office app spawns encoded PowerShell on $Computer$ by $User$"
    assert [d.name for d in det.drilldown_searches] == [
        "View the detection results for $Computer$", "View risk events for the last 7 days for $Computer$"]
    assert det.drilldown_searches[0].search == '%original_detection_search% | search Computer="$Computer$"'
    assert det.drilldown_searches[1].search.startswith('| from datamodel Risk.All_Risk | search normalized_risk_object IN ("$Computer$")')
    assert all(d.earliest_offset == "$info_min_time$" and d.latest_offset == "$info_max_time$" for d in det.drilldown_searches)
    assert det.tags.model_dump() == {
        "analytic_story": [idea.title], "asset_type": "Endpoint", "mitre_attack_id": ["T1059.001", "T1566.001"],
        "product": ["Splunk Enterprise", "Splunk Enterprise Security", "Splunk Cloud"], "security_domain": "endpoint",
        "throttling": {"fields": ["Computer", "User"], "period": "86400s"}}
    assert det.tests is None and "tests" not in det.model_dump(exclude_none=True)
    assert det.severity == "high"


def test_from_run_tests_block_and_fallbacks(idea, tmp_path):
    i = idea.model_copy(update={"attack_data_url": "https://x/a.log", "source_url": None, "false_positive_notes": None, "severity": "low"})
    d = DRAFT.model_copy(update={"group_fields": ["CommandLine"]})
    det = Detection.from_run(i, d, SOURCES, [], "production", tmp_path)
    assert det.tests[0].model_dump() == {"name": "True Positive Test", "test_type": "unit",
                                         "attack_data": [{"data": "https://x/a.log", "source": SYSMON, "sourcetype": SYSMON}]}
    assert det.references == [] and det.known_false_positives == "None identified."
    assert det.rba.risk_objects[0].model_dump() == {"field": "CommandLine", "type": "other", "score": 25}
    assert det.rba.message == idea.title and det.drilldown_searches[0].name == "View the detection results for $CommandLine$"
    assert det.tags.throttling.fields == ["CommandLine"] and det.severity == "low"


def test_from_run_hunting_omits_rba_drilldowns_throttling(idea, tmp_path):
    det = Detection.from_run(idea.model_copy(update={"type": "Hunting"}), DRAFT, SOURCES, [], "experimental", tmp_path)
    dumped = det.model_dump(exclude_none=True)
    assert det.type == "Hunting" and not {"rba", "drilldown_searches", "tests"} & dumped.keys()
    assert "throttling" not in dumped["tags"] and det.severity == "medium"
    props = det.conf_props(es=True)
    assert not [k for k in props if k.startswith("alert.suppress") or k.startswith("action.risk")]
    assert props["action.notable.param.severity"] == "medium"


def test_from_run_empty_group_fields(idea, tmp_path):
    draft = DRAFT.model_copy(update={"spl": "index=wineventlog | stats count", "group_fields": []})
    det = Detection.from_run(idea.model_copy(update={"type": "Hunting"}), draft, SOURCES, [], "experimental", tmp_path)
    assert det.rba is None and det.drilldown_searches is None
    with pytest.raises(ValueError, match="group fields"):
        Detection.from_run(idea, draft, SOURCES, [], "experimental", tmp_path)


@pytest.mark.parametrize("score, sev", [(25, "low"), (50, "medium"), (70, "high"), (90, "critical"), (60, "medium"), (10, "low")])
def test_severity_inverse(score, sev):
    det = Detection.model_validate({**DETECTION, "rba": {**DETECTION["rba"], "risk_objects": [{"field": "Computer", "type": "system", "score": score}]}})
    assert det.severity == sev


def test_conf_props(idea, tmp_path):
    det = Detection.from_run(idea, DRAFT, SOURCES, [], "production", tmp_path)
    props = det.conf_props()
    assert props["is_scheduled"] == 1 and props["cron_schedule"] == "*/15 * * * *"
    assert props["dispatch.earliest_time"] == "-25m@m" and props["dispatch.latest_time"] == "-5m@m"
    assert set(props["alert.suppress.fields"].split(",")) <= set(DRAFT.group_fields)
    assert props["alert.suppress.period"] == "86400s" and props["alert.severity"] == 4
    assert "enableSched" not in props and "counttype" not in props and not [k for k in props if k.startswith("action.")]
    es = det.conf_props(es=True)
    assert es["action.correlationsearch.label"] == idea.title and es["action.notable.param.rule_title"] == idea.title
    assert es["action.notable.param.security_domain"] == "endpoint" and es["action.risk"] == 1
    assert json.loads(es["action.risk.param._risk"]) == [
        {"risk_object_field": "Computer", "risk_object_type": "system", "risk_score": 70},
        {"risk_object_field": "User", "risk_object_type": "user", "risk_score": 70},
        {"threat_object_field": "ParentImage", "threat_object_type": "parent_process_name"},
        {"threat_object_field": "Image", "threat_object_type": "process_name"},
        {"threat_object_field": "CommandLine", "threat_object_type": "command"},
    ]
    assert es["action.risk.param._risk_message"] == det.rba.message


def test_to_yaml_round_trip_and_macro(idea, tmp_path):
    det = Detection.from_run(idea, DRAFT, SOURCES, FINDINGS, "experimental", tmp_path)
    text = det.to_yaml()
    assert Detection.model_validate(yaml.safe_load(text)) == det
    assert text.startswith("name: Office app spawns encoded PowerShell\n")  # insertion order kept
    assert yaml.safe_load(Detection.macro_yaml(idea.stem)) == {
        "name": "office_app_spawns_encoded_powershell_filter", "definition": "search *",
        "description": "Update this macro to limit the output results to filter out false positives."}


def test_version_bump_rule(idea, tmp_path):
    det = Detection.from_run(idea, DRAFT, SOURCES, [], "experimental", tmp_path)
    (tmp_path / f"{idea.stem}.yml").write_text(det.model_copy(update={"version": 3}).to_yaml())
    assert Detection.from_run(idea, DRAFT, SOURCES, [], "experimental", tmp_path).version == 3  # same search keeps version
    narrower = DRAFT.model_copy(update={"spl": SPL.replace("EventCode=1", "EventCode=1 User!=SYSTEM")})
    assert Detection.from_run(idea, narrower, SOURCES, [], "experimental", tmp_path).version == 4  # existing + 1
