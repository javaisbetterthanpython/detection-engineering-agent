import pytest

from detection_engineering_agent import spl

SYSMON = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
STEM = "office_app_spawns_encoded_powershell"
BASE = f'index=wineventlog sourcetype="{SYSMON}" EventCode=1 Image="*\\\\powershell.exe"'
GOOD = f"{BASE} | stats count min(_time) as firstTime max(_time) as lastTime by Computer User ParentImage"


@pytest.fixture
def check(inventory):
    return lambda s: spl.lint(s, inventory, STEM, [SYSMON])


# --- normalise / runnable / with_filter / window_seconds ---------------------


def test_normalise_strips_search_filter_and_whitespace():
    s = f"  search  {BASE}  |  stats count by  Computer | `{STEM}_filter` "
    n = spl.normalise(s)
    assert n == f"{BASE} | stats count by Computer"
    assert spl.normalise(n) == n


def test_runnable_prefixes_search_only_for_non_generating():
    assert spl.runnable(f"{BASE} | stats count by Computer").startswith("search index=")
    assert spl.runnable("search index=x | stats count by a") == "search index=x | stats count by a"
    assert spl.runnable("| tstats count where index=x by host") == "| tstats count where index=x by host"


def test_with_filter():
    assert spl.with_filter(f"search {BASE} | stats count by Computer", STEM).endswith(f" | `{STEM}_filter`")


@pytest.mark.parametrize("w,secs", [("-7d", 604800), ("-24h", 86400), ("-30m@m", 1800), ("-2w", 1209600), ("-10s", 10)])
def test_window_seconds(w, secs):
    assert spl.window_seconds(w) == secs


@pytest.mark.parametrize("w", ["7d", "-7x", "now", "-7d extra", ""])
def test_window_seconds_invalid(w):
    with pytest.raises(ValueError):
        spl.window_seconds(w)


# --- field extraction --------------------------------------------------------


def test_referenced_fields():
    s = f"{BASE} ParentImage!=x (User IN (a,b)) | stats count dc(CommandLine) by Computer, User | sort 0 - count"
    assert spl.referenced_fields(s) == {"EventCode", "Image", "ParentImage", "User", "CommandLine", "Computer"}


def test_referenced_fields_skips_options_and_builtins():
    s = f'{BASE} | rex field=_raw "powershell" | fillnull value=NA User | spath input=_raw | stats count by User'
    assert spl.referenced_fields(s) == {"EventCode", "Image", "User"}


def test_derived_fields():
    s = ('index=x | eval delta=now()-_time | rename Image as proc | rex "(?<enc>-enc)" '
         "| lookup l Image OUTPUT verdict, score | lookup m Image OUTPUTNEW tag | stats count by proc")
    assert spl.derived_fields(s) == {"delta", "proc", "enc", "verdict", "score", "tag"}


def test_derived_fields_multi_assignment_eval():
    s = 'index=x | eval a=1, b=if(c=="1", "y", "z"), d=lower(D) | stats count by b'
    assert spl.derived_fields(s) >= {"a", "b", "d"} and "c" not in spl.derived_fields(s)


def test_derived_fields_nested_eval():
    assert spl.derived_fields("index=x | appendpipe [ eval computer=lower(Computer) ] | stats count by computer") == {"computer"}


def test_referenced_fields_ignores_quoted_values():
    assert spl.referenced_fields('index=x CommandLine="*computer=* a>b" | stats count by Computer') == {"CommandLine", "Computer"}


def test_referenced_fields_is_case_sensitive():
    assert spl.referenced_fields("index=x Count=1 Host=a | stats count by User") == {"Count", "Host", "User"}


def test_derived_fields_ignores_quoted_as_and_output():
    s = 'index=x CommandLine="* as admin*" Image="a OUTPUT b" admin=1 | stats count by Computer'
    assert spl.derived_fields(s) == set()


# --- group_fields / indexes_in / sourcetypes_in / exclusions -----------------


def test_group_fields_stats_by():
    assert spl.group_fields(GOOD) == ["Computer", "User", "ParentImage"]
    assert spl.group_fields(f"{BASE} | stats count by a, b | stats sum(count) by _time, span=20m, a") == ["a"]


def test_group_fields_tstats_table_none():
    assert spl.group_fields("| tstats count where index=x by host, Processes.process_name") == ["host", "Processes.process_name"]
    assert spl.group_fields(f"{BASE} | table Computer, User Image") == ["Computer", "User", "Image"]
    assert spl.group_fields(f"{BASE} | stats count") == []
    assert spl.group_fields(BASE) == []


def test_group_fields_case_insensitive():
    assert spl.group_fields(f"{BASE} | STATS count BY Computer User") == ["Computer", "User"]
    assert spl.group_fields(f"{BASE} | Table Computer") == ["Computer"]


def test_indexes_and_sourcetypes_in():
    s = 'index=a index="b" index IN (c, "d") sourcetype=x sourcetype="y:z" sourcetype IN (w)'
    assert spl.indexes_in(s) == {"a", "b", "c", "d"}
    assert spl.sourcetypes_in(s) == {"x", "y:z", "w"}
    assert spl.indexes_in("_index_earliest=-1d sourcetype=x") == set()
    assert spl.indexes_in("(index=a OR index=b) x=1") == {"a", "b"}
    assert spl.sourcetypes_in("(sourcetype=a OR sourcetype=b) x=1") == {"a", "b"}


def test_indexes_in_subsearch_bracket():
    assert spl.indexes_in("index=a [search index=b] | stats count by Computer") == {"a", "b"}


def test_exclusions():
    s = f'{BASE} NOT User="NT AUTHORITY\\\\SYSTEM" ParentImage!=*\\\\explorer.exe NOT Computer=DC01 | stats count by User'
    assert spl.exclusions(s) == ['NOT User="NT AUTHORITY\\\\SYSTEM"', "ParentImage!=*\\\\explorer.exe", "NOT Computer=DC01"]
    assert spl.exclusions(GOOD) == []
    assert spl.exclusions("index=x (NOT Computer=DC01 OR User!=svc) | stats count") == ["NOT Computer=DC01", "User!=svc"]
    s = f'{BASE} NOT (IntegrityLevel="High" OR IntegrityLevel="System") NOT (User="NT AUTHORITY\\\\SYSTEM") | stats count by User'
    assert spl.exclusions(s) == ['NOT (IntegrityLevel="High" OR IntegrityLevel="System")', 'NOT (User="NT AUTHORITY\\\\SYSTEM")']
    assert spl.exclusions(f"{BASE} NOT ((User=a OR User=b) AND Computer=c) | stats count by User") == ["NOT ((User=a OR User=b) AND Computer=c)"]


def test_exclusions_where_not():
    seg = 'where NOT (IntegrityLevel="High" OR IntegrityLevel="System")'
    s = f'{BASE} | eval p=lower(ParentImage) | where match(p, "(winword|excel)\\.exe$") | {seg} | stats count by User'
    assert spl.exclusions(s) == [seg]
    assert spl.exclusions(f'{BASE} | where NOT match(User, "^CORP\\\\(svc_fin)$") AND ParentImage!=x | stats count by User') == [
        "ParentImage!=x", 'where NOT match(User, "^CORP\\\\(svc_fin)$") AND ParentImage!=x']
    assert spl.exclusions(f'{BASE} | where isnotnull(CommandLine) | stats count by User') == []


def test_exclusions_not_in():
    s = f'{BASE} NOT User IN ("svc_a","svc_b") NOT Computer in (DC01) | stats count by Computer'
    assert spl.exclusions(s) == ['NOT User IN ("svc_a","svc_b")', "NOT Computer in (DC01)"]


SUB = f"{BASE} [search index=wineventlog EventCode=3 | stats count by Computer ProcessGuid | fields Computer ProcessGuid]"


def test_split_keeps_subsearch_whole():
    assert spl._split(f"{SUB} | stats count by Computer User | sort - count") == [SUB, "stats count by Computer User", "sort - count"]
    assert spl.group_fields(f"{SUB} | stats count by Computer User") == ["Computer", "User"]
    assert spl.referenced_fields(f"{SUB} | stats count by Computer User") == {"EventCode", "Image", "Computer", "ProcessGuid", "User"}
    assert spl._names("Computer]") == ["Computer"]


# --- bucketed ----------------------------------------------------------------


def test_bucketed_skips_subsearch_stats():
    assert spl.bucketed(f"{SUB} | stats count by Computer User") == f"{SUB} | bin _time span=20m | stats count by _time Computer User"


def test_bucketed_ignores_by_inside_quotes_and_parens():
    seg = 'stats count(eval(match(CommandLine, "spawned by "))) as n by Computer'
    assert spl.bucketed(f"{BASE} | {seg}") == f"{BASE} | bin _time span=20m | {seg.replace('n by', 'n by _time')}"
    seg = 'stats count(eval(CommandLine="by foo")) by Computer'
    assert spl.bucketed(f"{BASE} | {seg}") == f"{BASE} | bin _time span=20m | {seg.replace(') by', ') by _time')}"


def test_bucketed_already_bucketed_unchanged():
    for s in (f"{BASE} | bin _time span=20m | stats count by _time Computer", "| tstats count where index=x by _time span=20m host"):
        assert spl.bucketed(s) == s


def test_bucketed_stats_with_by():
    assert spl.bucketed(f"{BASE} | stats count by Computer User | sort - count") == (
        f"{BASE} | bin _time span=20m | stats count by _time Computer User | sort - count"
    )


def test_bucketed_stats_without_by():
    assert spl.bucketed(f"{BASE} | stats count", span="5m") == f"{BASE} | bin _time span=5m | stats count by _time"


def test_bucketed_case_insensitive():
    assert spl.bucketed(f"{BASE} | Stats count BY Computer") == f"{BASE} | bin _time span=20m | Stats count by _time Computer"
    assert spl.bucketed("| TSTATS count where index=x BY host") == "| TSTATS count where index=x by _time span=20m host"


def test_bucketed_tstats():
    assert spl.bucketed("| tstats count where index=x by host | sort - count") == (
        "| tstats count where index=x by _time span=20m host | sort - count"
    )
    assert spl.bucketed("| tstats count where index=x") == "| tstats count where index=x by _time span=20m"


def test_bucketed_keeps_quoted_pipes():
    assert spl.bucketed('index=x | rex "(?<a>foo|bar)" | stats count by a') == (
        'index=x | rex "(?<a>foo|bar)" | bin _time span=20m | stats count by _time a'
    )
    assert spl.bucketed('index=x CommandLine="a|b" | stats count') == 'index=x CommandLine="a|b" | bin _time span=20m | stats count by _time'
    s = 'index=x CommandLine="say \\"| stats\\" x" | stats count by a | sort - count'
    assert spl.bucketed(s) == 'index=x CommandLine="say \\"| stats\\" x" | bin _time span=20m | stats count by _time a | sort - count'


def test_group_fields_ignores_quoted_pipes():
    assert spl.group_fields('index=x CommandLine="a|table z" | stats count by a') == ["a"]


def test_bucketed_passthrough():
    assert spl.bucketed(BASE) == BASE
    assert spl.bucketed(f"{BASE} | table Computer") == f"{BASE} | table Computer"


# --- lint rules --------------------------------------------------------------


def test_lint_clean(check):
    assert check(GOOD) == spl.Lint()


@pytest.mark.parametrize("bad", ["earliest=-1d", "latest=now", "_index_earliest=-1d", "_index_latest=now"])
def test_lint_rule1_time_modifiers(check, bad):
    assert any("earliest" in e for e in check(f"{BASE} {bad} | stats count by User").errors)


@pytest.mark.parametrize("cmd", ["head 10", "delete", "collect index=x", "outputlookup f.csv", "map search=x", "rest /services"])
def test_lint_rule2_banned(check, cmd):
    assert any("banned command" in e for e in check(f"{GOOD} | {cmd}").errors)


def test_lint_rule2_banned_word_inside_value(check):
    assert not any("banned" in e for e in check(f"{GOOD} | search User=headless | stats count by User").errors)


def test_lint_rule3_index_required(check):
    assert any("index" in e for e in check(f'sourcetype="{SYSMON}" EventCode=1 | stats count by User').errors)
    assert any("index=*" in e for e in check(f'index=* sourcetype="{SYSMON}" | stats count by User').errors)
    assert any("index=*" in e for e in check(f'index="*" sourcetype="{SYSMON}" | stats count by User').errors)
    assert check("`sysmon` EventCode=1 | stats count by User").errors == []
    assert check("| tstats count where index=wineventlog by host").errors == []


def test_lint_rule4_unknown_index_sourcetype(check):
    errs = check(f'index=nope sourcetype="nope:x" | stats count by User').errors
    assert "unknown index 'nope'" in errs and "unknown sourcetype 'nope:x'" in errs
    assert not [e for e in check(GOOD).errors if "unknown index" in e or "unknown sourcetype" in e]


def test_lint_rule5_macros(check):
    assert check(f"{GOOD} | `security_content_ctime(firstTime)` | `{STEM}_filter`").errors == []
    assert "unknown macro '`nope`'" in check(f"{GOOD} | `nope`").errors


def test_lint_rule6_unknown_field(check):
    r = check(f"{BASE} ParentCommandline=\"*x*\" | stats count by User")
    assert "unknown field 'ParentCommandline' (did you mean 'ParentCommandLine'?)" in r.errors
    r = check(f"{BASE} OriginalFileName=x | stats count by User")
    assert r.errors == ["unknown field 'OriginalFileName' (not in available_fields)"] and r.warnings == []


def test_lint_rule6_function_arg_bypass(check):
    for s in (f'{BASE} | where match(OriginalFileName, "(?i)powershell") | stats count by User',
              f"{BASE} | eval o=lower(OriginalFileName) | stats count by o"):
        assert check(s).errors == ["unknown field 'OriginalFileName' (not in available_fields)"]
    assert check(f'{BASE} | eval p=lower(ParentImage) | where match(p, "x") AND isnotnull(p) AND len(CommandLine)>3 | stats count by p').errors == []
    # nested calls: the inner function name is not a field, the inner real field is still checked
    for s in (f'{BASE} | where match(lower(CommandLine), "x") | stats count by User',
              f'{BASE} | eval n=mvcount(split(CommandLine, " ")) | stats count by n',
              f'{BASE} | eval p=lower(coalesce(ParentImage, "")) | stats count by p',
              f"{BASE} | eval l=len(trim(CommandLine)) | stats count by l",
              f"{BASE} | eval t=tostring(now()) | stats count by t",
              f'{BASE} | where match(lower(Image), "x") | eval c=lower(coalesce(CommandLine, "")) | stats count by Computer c'):
        assert check(s).errors == [], s
    for s in (f'{BASE} | where match(lower(OriginalFileName), "x") | stats count by User',
              f"{BASE} | eval o=lower(OriginalFileName) | stats count by o",
              # field references outside comparisons / functions
              f'{BASE} | rex field=OriginalFileName "(?<ofn>.*)" | stats count by ofn',
              f"{BASE} | fillnull value=NA OriginalFileName | stats count by User",
              f"{BASE} | table Computer OriginalFileName",
              f"{BASE} | fields - OriginalFileName | stats count by User"):
        assert check(s).errors == ["unknown field 'OriginalFileName' (not in available_fields)"], s
    assert check(f"{BASE} | fields + Computer User | fillnull User | table Computer, User | fields - _raw | table *").errors == []


def test_referenced_fields_function_args():
    s = 'index=x | where match(OriginalFileName, "lower(Fake)") AND len(CommandLine)>3 | eval o=lower(Image) | stats count by o'
    assert spl.referenced_fields(s) >= {"OriginalFileName", "CommandLine", "Image"} and "Fake" not in spl.referenced_fields(s)


def test_lint_rule6_tstats_downgrades_to_warning(check):
    r = check("| tstats count where index=wineventlog ParentCommandline=x by host")
    assert r.errors == [] and any("ParentCommandline" in w for w in r.warnings)


def test_lint_rule6_options_and_derived_not_fields(check):
    s = f'{BASE} | rex field=_raw "(?<enc>-enc)" | fillnull value=NA enc | eval delta=1 | stats count by User enc delta'
    assert check(s).errors == []


def test_lint_rule4_parenthesised_index(check):
    assert check("(index=wineventlog OR index=wineventlog) EventCode=1 | stats count by User").errors == []


def test_lint_rule6_nested_eval_is_derived(check):
    assert check("index=wineventlog | appendpipe [ eval computer=lower(Computer) ] | stats count by computer").errors == []


def test_lint_rule6_falls_back_to_sources_when_no_sourcetype(check):
    assert check("index=wineventlog EventCode=1 | stats count by Computer").errors == []
    assert "unknown field 'computer' (did you mean 'Computer'?)" in check("index=wineventlog | stats count by computer").errors


def test_lint_rule6_multi_assignment_eval_and_case_typos(check):
    assert check("index=wineventlog | eval user=lower(User), computer=lower(Computer) | stats count by computer").errors == []
    r = check("index=wineventlog Count=1 Host=a | stats count by User")
    assert {"unknown field 'Count' (not in available_fields)", "unknown field 'Host' (not in available_fields)"} <= set(r.errors)
    assert r.warnings == []


def test_lint_rule7_bare_wildcard(check):
    assert any("wildcard" in e for e in check(f"{BASE} *powershell* | stats count by User").errors)
    assert any("wildcard" in e for e in check(f'{BASE} _raw="*enc*" | stats count by User').errors)
    assert not any("wildcard" in e for e in check(GOOD).errors)


def test_lint_rule7_ignores_wildcards_inside_quotes(check):
    for v in ['"* -enc *"', '"* -ep bypass *"', '"*powershell* *-enc*"']:
        assert not any("wildcard" in e for e in check(f"{BASE} CommandLine={v} | stats count by User").errors)
    assert any("wildcard" in e for e in check(f'{BASE} CommandLine="a | b" *x | stats count by User').errors)


def test_lint_rule6_ignores_key_value_inside_quotes(check):
    assert check(f'{BASE} CommandLine="*computer=*" | stats count by Computer').errors == []


def test_lint_rule6_ignores_quoted_as(check):
    r = check(f'{BASE} CommandLine="* as admin*" admin=1 | stats count by Computer')
    assert r.errors == ["unknown field 'admin' (not in available_fields)"]


def test_lint_rule6_subsearch_fields_table(check):
    for tail in ("fields Computer]", "table Computer]"):
        s = f"{BASE} [search index=wineventlog EventCode=3 | stats count by Computer | {tail} | stats count by Computer User"
        assert not any("unknown field" in e for e in check(s).errors)


def test_lint_rules1_2_ignore_quoted_text(check):
    r = check(f'{BASE} | rex field=CommandLine "(?<verb>download|run|dump)" | stats count by Computer verb')
    assert r.errors == []
    assert check(f'{BASE} CommandLine="*latest=*" | stats count by Computer').errors == []
    assert check(f'{BASE} CommandLine="`x`" | stats count by Computer').errors == []


def test_lint_rule8_needs_group_fields(check):
    assert any("group fields" in e for e in check(f"{BASE} | stats count").errors)
    assert any("group fields" in e for e in check(f"{BASE} | stats count by _time").errors)
    assert any("group fields" in e for e in check(f"{BASE} | stats count by Computer | stats count").errors)
    assert check(f"{BASE} | stats count BY Computer User").errors == []


def test_lint_rule8_needs_grouping_segment(check):
    assert any("stats" in e for e in check(BASE).errors)
    assert any("stats" in e for e in check(f"{BASE} | sort - _time").errors)
    assert check(f"{BASE} | table Computer User").errors == []
    r = check(f"{BASE} (CommandLine=\"*{'a' * 4000}*\") | stats count by User")
    assert "search longer than 4000 chars" in r.warnings


@pytest.mark.parametrize("construct", ["transaction Computer", "streamstats count by User", "bin _time span=1h", "bin _time span=1d",
                                       "bin _time span=1w", "bin _time span=1mon",
                                       "eval age=now()-earliest(_time)"])
def test_lint_rule9_schedule_warnings(check, construct):
    r = check(f"{BASE} | {construct} | stats count by User")
    assert r.errors == [] and any(w.startswith("schedule:") and "20-minute" in w for w in r.warnings)


def test_lint_rule9_span_20m_ok(check):
    assert spl.bucketed(GOOD) and check(spl.bucketed(GOOD)).warnings == []


# --- rows helpers ------------------------------------------------------------

ROWS = [
    {"ParentImage": "explorer.exe", "CommandLine": "a", "count": "120"},
    {"ParentImage": "explorer.exe", "CommandLine": "b", "count": "95"},
    {"ParentImage": "services.exe", "CommandLine": "c", "count": "30"},
    {"ParentImage": "explorer.exe", "CommandLine": "d", "count": "88"},
    {"ParentImage": "winword.exe", "CommandLine": "e", "count": "3"},
]


def test_top_values_weighted_and_skips_high_cardinality():
    tv = spl.top_values(ROWS, ["ParentImage", "CommandLine"], n=2)
    assert tv == {"ParentImage": [("explorer.exe", 303), ("services.exe", 30)]}
    assert spl.top_values([{"a": "x"}, {"a": "y"}], ["a"]) == {}  # 100 % distinct
    assert spl.top_values([{"a": "x"}, {"a": "x"}], ["a"]) == {"a": [("x", 2)]}  # no count -> weight 1
    assert spl.top_values([{"a": "x", "count": 0}, {"a": "x", "count": "2"}], ["a"]) == {"a": [("x", 2)]}  # zero stays zero
    assert spl.top_values([], ["a"]) == {}


def test_high_cardinality():
    assert spl.high_cardinality(ROWS, ["ParentImage", "CommandLine"], min_rows=5) == [("CommandLine", 5, 5)]
    assert spl.high_cardinality(ROWS, ["ParentImage", "CommandLine"]) == []  # 5 rows < the 10-row floor
    assert spl.high_cardinality([{"Computer": "WS01", "count": "1"}], ["Computer"]) == []  # run 2: "1 distinct / 1 rows" misled tune
    assert spl.high_cardinality([], ["a"]) == []


def test_project():
    assert spl.project(ROWS, ["ParentImage", "count", "missing"], n=2) == [
        {"ParentImage": "explorer.exe", "count": "120"},
        {"ParentImage": "explorer.exe", "count": "95"},
    ]


# --- rewrite_index -----------------------------------------------------------


def test_rewrite_index():
    assert spl.rewrite_index("search index=x a=1", "atk") == "search index=atk a=1"
    assert spl.rewrite_index('search index="x" a=1', "atk") == "search index=atk a=1"
    assert spl.rewrite_index("search index IN (a, b) a=1", "atk") == "search index=atk a=1"
    assert spl.rewrite_index("search index=x [search index=y ] | stats count", "atk", host="h-0") == (
        'search index=atk host="h-0" [search index=atk ] | stats count'
    )
    assert spl.rewrite_index("search index=x [search index=y] | stats count", "atk", host="h") == (
        'search index=atk host="h" [search index=atk] | stats count'
    )
    assert spl.rewrite_index("| tstats count where index=x by host", "atk", host="h") == '| tstats count where index=atk host="h" by host'
    assert spl.rewrite_index("search _index_earliest=-1d index=x", "atk") == "search _index_earliest=-1d index=atk"
    assert spl.rewrite_index("search (index=a OR index=b) x=1 | stats count", "atk", host="h") == (
        'search (index=atk host="h" OR index=atk) x=1 | stats count'
    )


def test_rewrite_index_leading_macro_gets_scope():
    assert spl.rewrite_index("search `sysmon` EventCode=1 | stats count by Computer", "atk", host="h") == (
        'search index=atk host="h" `sysmon` EventCode=1 | stats count by Computer'
    )
    assert spl.rewrite_index("search `sysmon` EventCode=1", "atk") == "search index=atk `sysmon` EventCode=1"
    assert spl.rewrite_index("| tstats count where `sysmon` by host", "atk", host="h") == '| tstats count where index=atk host="h" `sysmon` by host'
