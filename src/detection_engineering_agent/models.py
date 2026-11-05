import datetime
import json
import re
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .prompts import SCHEDULE

Severity = Literal["low", "medium", "high", "critical"]
IdeaType = Literal["TTP", "Anomaly", "Hunting"]
MitreId = Annotated[str, Field(pattern=r"^T\d{4}(\.\d{3})?$")]
Uuid4 = Annotated[str, Field(pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")]

SOURCETYPE_META = [  # (regex, data_source, asset_type, security_domain); matched with re.I, first match wins
    (r"sysmon", "Sysmon EventID 1", "Endpoint", "endpoint"),
    (r"powershell", "Powershell Script Block Logging 4104", "Endpoint", "endpoint"),
    (r"wineventlog:security|:4688", "Windows Event Log Security 4688", "Endpoint", "endpoint"),
    (r"wineventlog", "Windows Event Log", "Endpoint", "endpoint"),
    (r"linux|syslog|auditd", "Linux Auditd", "Endpoint", "endpoint"),
    (r"cloudtrail", "AWS CloudTrail", "AWS Account", "threat"),
    (r"azure|o365|m365|office365", "Azure Monitor Activity", "Azure Tenant", "threat"),
    (r"\bgcp\b|google", "Google Cloud Platform", "GCP Account", "threat"),
    (r"okta|auth0|\bduo\b", "Okta", "Okta Tenant", "identity"),
    (r"zeek|\bbro\b|pan(os)?[:_]|firewall|netflow|suricata|\bdns\b", "Zeek", "Network", "network"),
    (r"proxy|squid|zscaler|\bweb\b|\biis\b|nginx|apache", "Nginx Access", "Web Server", "network"),
]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --- 4.1 idea ---------------------------------------------------------------


class LogSource(Strict):
    product: str
    keywords: list[str] = Field(min_length=1)
    fields: list[str] = []


class AttackExample(Strict):
    keyword: str
    raw: str


class Idea(Strict):
    id: Uuid4
    title: str = Field(min_length=1, max_length=99)
    source_url: str | None = None
    summary: str = Field(min_length=1, max_length=600)
    attack_steps: list[str] = Field(min_length=1)
    indicators: list[str] = []
    mitre_attack_id: list[MitreId]
    type: IdeaType
    severity: Severity = "medium"
    log_sources: list[LogSource] = Field(min_length=1)
    sourcetypes: list[str] = []
    max_hits_per_day: int | None = None
    false_positive_notes: str | None = None
    attack_examples: list[AttackExample] = []
    attack_data_url: str | None = None

    @property
    def stem(self) -> str:
        return re.sub(r"[^a-z0-9]+", "_", self.title.lower()).strip("_")

    @model_validator(mode="after")
    def _stem_not_empty(self) -> "Idea":
        if self.stem == "":
            raise ValueError("title must contain at least one ASCII letter or digit (stem would be empty)")
        return self

    @property
    def threshold(self) -> int:
        return self.max_hits_per_day or {"TTP": 5, "Anomaly": 20, "Hunting": 100}[self.type]

    @classmethod
    def load(cls, path: str | Path) -> "Idea":
        return cls.model_validate(yaml.safe_load(Path(path).read_text()))


# --- 4.2 inventory ------------------------------------------------------------


class Sourcetype(Strict):
    name: str
    count: int
    fields: dict[str, list[str]] = {}
    sample: str | None = None


class Index(Strict):
    name: str
    events: int
    sourcetypes: list[Sourcetype] = []


class Inventory(Strict):
    fetched_at: str
    window: str
    macros: list[str] = []
    indexes: list[Index] = []

    def _sourcetypes(self):
        return ((ix, st) for ix in self.indexes for st in ix.sourcetypes)

    def sourcetype_names(self) -> set[str]:
        return {st.name for _, st in self._sourcetypes()}

    def index_names(self) -> set[str]:
        return {ix.name for ix in self.indexes}

    def fields_for(self, sourcetype: str) -> dict[str, list[str]]:
        return {k: v for _, st in self._sourcetypes() if st.name == sourcetype for k, v in st.fields.items()}

    def sample_for(self, sourcetype: str) -> str | None:
        return next((st.sample for _, st in self._sourcetypes() if st.name == sourcetype and st.sample), None)

    def find(self, index: str, sourcetype: str) -> Sourcetype:
        for ix, st in self._sourcetypes():
            if ix.name == index and st.name == sourcetype:
                return st
        raise KeyError(f"{index}/{sourcetype}")


# --- 4.3 pipeline state elements ---------------------------------------------


class Source(Strict):
    index: str
    sourcetype: str
    score: int
    data_source: str
    asset_type: str
    security_domain: str


class Example(Strict):
    sourcetype: str
    raw: str
    host: str


class Draft(Strict):
    n: int
    origin: Literal["author", "tune", "refine"]
    spl: str
    group_fields: list[str]
    fields_used: list[str]


# --- 4.5 inference outputs ----------------------------------------------------


class IdeaDraft(Strict):
    title: str = Field(max_length=99)
    summary: str = Field(max_length=600)
    attack_steps: list[str]
    indicators: list[str]
    mitre_attack_id: list[str]
    type: IdeaType
    severity: Severity
    log_sources: list[LogSource]
    false_positive_notes: str | None = None
    attack_examples: list[AttackExample] = []


class IdeasOut(Strict):
    ideas: list[IdeaDraft]


class SplOut(Strict):
    spl: str


class Finding(Strict):
    category: Literal["evasion", "false_positive", "logic", "performance", "brittleness"]
    severity: Severity
    detail: str
    fix_hint: str


class EvasionEvent(Strict):
    sourcetype: str
    raw: str
    note: str


class ReviewOut(Strict):
    findings: list[Finding]
    evasion_events: list[EvasionEvent]


class ReviewRound(Strict):
    round: int
    draft: int
    findings: list[Finding]
    evasion_events: list[EvasionEvent]


def schema(model: type[BaseModel]) -> dict:
    return model.model_json_schema()


# --- 4.4 detection YAML -------------------------------------------------------


class Drilldown(Strict):
    name: str
    search: str
    earliest_offset: str
    latest_offset: str


class RiskObject(Strict):
    field: str
    type: Literal["user", "system", "other"]
    score: int


class ThreatObject(Strict):
    field: str
    type: Literal["command", "process_name", "parent_process_name", "ip_address", "url", "file_name"]


class Rba(Strict):
    message: str
    risk_objects: list[RiskObject] = Field(min_length=1)
    threat_objects: list[ThreatObject]


class Throttling(Strict):
    fields: list[str]
    period: str


class Tags(Strict):
    analytic_story: list[str]
    asset_type: str
    mitre_attack_id: list[str]
    product: list[str]
    security_domain: Literal["endpoint", "network", "threat", "identity", "access", "audit"]
    throttling: Throttling | None = None


class AttackData(Strict):
    data: str
    source: str
    sourcetype: str


class Test(Strict):
    name: str
    attack_data: list[AttackData]
    test_type: str


# --- 7.5 rendering tables -----------------------------------------------------

SEVERITY_SCORE = {"low": 25, "medium": 50, "high": 70, "critical": 90}
SEVERITY_ALERT = {"low": 2, "medium": 3, "high": 4, "critical": 5}
USER_FIELDS = {"user", "src_user", "username", "user_name", "account_name", "useridentity.arn"}
SYSTEM_FIELDS = {"computer", "host", "dest", "src", "dvc", "computername", "hostname", "src_ip", "dest_ip"}
THREAT_TYPES = {  # lower-cased group field -> ThreatObject.type
    "commandline": "command", "process_command_line": "command",
    "image": "process_name", "process_name": "process_name", "new_process_name": "process_name",
    "parentimage": "parent_process_name", "parent_process_name": "parent_process_name", "creator_process_name": "parent_process_name",
    "dest_ip": "ip_address", "destinationip": "ip_address",
    "url": "url",
    "file_name": "file_name", "targetfilename": "file_name",
}
PRODUCTS = ["Splunk Enterprise", "Splunk Enterprise Security", "Splunk Cloud"]
RISK_DRILLDOWN = (
    '| from datamodel Risk.All_Risk | search normalized_risk_object IN ("${k}$") starthoursago=168 '
    "| stats count min(_time) as firstTime max(_time) as lastTime values(search_name) as \"Search Name\" "
    'values(risk_message) as "Risk Message" values(analyticstories) as "Analytic Stories" '
    'values(annotations._all) as "Annotations" values(annotations.mitre_attack.mitre_tactic) as "ATT&CK Tactics" '
    "by normalized_risk_object"
)


def _risk_type(field: str) -> str | None:
    f = field.lower()
    return "user" if f in USER_FIELDS else "system" if f in SYSTEM_FIELDS else None


def _product(idea: Idea, sourcetype: str) -> str:
    st = sourcetype.lower()
    return next((ls.product for ls in idea.log_sources if any(kw.lower() in st for kw in ls.keywords)), sourcetype)


class Detection(Strict):
    name: str
    id: str
    version: int
    date: str
    author: str
    status: Literal["production", "experimental"]
    type: IdeaType
    description: str
    data_source: list[str]
    search: str
    how_to_implement: str
    known_false_positives: str
    references: list[str]
    drilldown_searches: list[Drilldown] | None = None
    rba: Rba | None = None
    tags: Tags
    tests: list[Test] | None = None

    @classmethod
    def from_run(cls, idea: Idea, draft: Draft, sources: list[Source], findings: list[Finding], status: str, out_dir: str | Path) -> "Detection":
        from . import spl  # lazy: spl imports models

        stem, hunting, score = idea.stem, idea.type == "Hunting", SEVERITY_SCORE[idea.severity]
        search = spl.with_filter(draft.spl, stem)
        used = spl.sourcetypes_in(search) | spl.indexes_in(search)
        referenced = [s for s in sources if s.sourcetype in used or s.index in used] or sources
        drilldowns = rba = throttling = None
        if not hunting:
            if not draft.group_fields:
                raise ValueError(f"draft {draft.n} has no group fields; rba/drilldowns need at least one")
            risk = [RiskObject(field=g, type=t, score=score) for g in draft.group_fields if (t := _risk_type(g))]
            risk = risk or [RiskObject(field=draft.group_fields[0], type="other", score=score)]
            k = risk[0].field
            first = {o.type: o.field for o in reversed(risk)}  # first field per risk type
            message = idea.title + "".join(f" {w} ${first[t]}$" for w, t in (("on", "system"), ("by", "user")) if t in first)
            drilldowns = [
                Drilldown(name=f"View the detection results for ${k}$", search=f'%original_detection_search% | search {k}="${k}$"',
                          earliest_offset="$info_min_time$", latest_offset="$info_max_time$"),
                Drilldown(name=f"View risk events for the last 7 days for ${k}$", search=RISK_DRILLDOWN.format(k=k),
                          earliest_offset="$info_min_time$", latest_offset="$info_max_time$"),
            ]
            rba = Rba(
                message=message, risk_objects=risk,
                threat_objects=[ThreatObject(field=g, type=THREAT_TYPES[g.lower()]) for g in draft.group_fields if g.lower() in THREAT_TYPES],
            )
            throttling = Throttling(fields=[o.field for o in risk], period="86400s")
        fps = [f"{f.detail} ({f.severity})" for f in findings if f.category == "false_positive"]
        version, existing = 1, Path(out_dir) / f"{stem}.yml"
        if existing.exists():
            prev = yaml.safe_load(existing.read_text())
            version = prev["version"] + (prev["search"] != search)
        return cls(
            name=idea.title,
            id=idea.id,
            version=version,
            date=datetime.date.today().isoformat(),
            author="detection-engineering-agent",
            status=status,
            type=idea.type,
            description=f"{idea.summary}\n\nDetects: {'; '.join(idea.attack_steps)}",
            data_source=list(dict.fromkeys(s.data_source for s in referenced)),
            search=search,
            how_to_implement="".join(f"Ingest {_product(idea, s.sourcetype)} as sourcetype {s.sourcetype} into index {s.index}. " for s in sources)
            + f"Fields used: {', '.join(draft.fields_used)}. Adjust the index/sourcetype or the {stem}_filter macro for your environment.",
            known_false_positives=(idea.false_positive_notes or "None identified.") + (" Review findings: " + "; ".join(fps) if fps else ""),
            references=[idea.source_url] if idea.source_url else [],
            drilldown_searches=drilldowns,
            rba=rba,
            tags=Tags(
                analytic_story=[idea.title], asset_type=sources[0].asset_type, mitre_attack_id=idea.mitre_attack_id, product=PRODUCTS,
                security_domain=sources[0].security_domain,
                throttling=throttling,
            ),
            tests=[Test(name="True Positive Test", test_type="unit",
                        attack_data=[AttackData(data=idea.attack_data_url, source=sources[0].sourcetype, sourcetype=sources[0].sourcetype)])]
            if idea.attack_data_url else None,
        )

    @property
    def severity(self) -> str:
        if not self.rba:
            return "medium"
        top = max(o.score for o in self.rba.risk_objects)
        return max((k for k, v in SEVERITY_SCORE.items() if v <= top), key=SEVERITY_SCORE.get, default="low")

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.model_dump(exclude_none=True), sort_keys=False, width=10_000, allow_unicode=True)

    @staticmethod
    def macro_yaml(stem: str) -> str:
        return yaml.safe_dump(
            {"name": f"{stem}_filter", "definition": "search *",
             "description": "Update this macro to limit the output results to filter out false positives."},
            sort_keys=False,
        )

    def conf_props(self, es: bool = False) -> dict[str, str | int]:
        sev = self.severity
        props: dict[str, str | int] = {
            "is_scheduled": 1, "cron_schedule": SCHEDULE["cron"], "schedule_window": "auto", "allow_skew": "100%",
            "dispatch.earliest_time": "-25m@m", "dispatch.latest_time": "-5m@m", "description": self.description,
            "alert_type": "number of events", "alert_comparator": "greater than", "alert_threshold": 0,
            "alert.severity": SEVERITY_ALERT[sev], "alert.track": 1, "alert.digest_mode": 0,
        }
        if self.tags.throttling:
            props |= {"alert.suppress": 1, "alert.suppress.fields": ",".join(self.tags.throttling.fields),
                      "alert.suppress.period": self.tags.throttling.period}
        if es:
            props |= {
                "action.notable": 1, "action.notable.param.rule_title": self.name, "action.notable.param.rule_description": self.description,
                "action.notable.param.security_domain": self.tags.security_domain, "action.notable.param.severity": sev,
                "action.correlationsearch.enabled": 1, "action.correlationsearch.label": self.name,
            }
            if self.rba:
                props |= {
                    "action.risk": 1, "action.risk.param._risk_message": self.rba.message, "action.risk.param._risk_score": 0,
                    "action.risk.param._risk": json.dumps(
                        [{"risk_object_field": o.field, "risk_object_type": o.type, "risk_score": o.score} for o in self.rba.risk_objects]
                        + [{"threat_object_field": t.field, "threat_object_type": t.type} for t in self.rba.threat_objects]
                    ),
                }
        return props

