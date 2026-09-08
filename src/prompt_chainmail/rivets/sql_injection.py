from __future__ import annotations

import re
from functools import lru_cache

from prompt_chainmail.rivets.base import FnRivet, NextFn, Rivet
from prompt_chainmail.rivets.types import SecurityFlags, ThreatLevel
from prompt_chainmail.rivets.utils import apply_threat_penalty
from prompt_chainmail.types import ChainmailContext, ChainmailResult

_SOURCES = (
    r"(?i)\bunion\s+(?:all\s+)?select\b",
    r"(?i)\bunion\s+(?:distinct\s+)?select\b",
    r"(?i);\s*(?:drop|truncate)\s+(?:table|database|schema)\b",
    r"(?i);\s*(?:create|alter)\s+(?:table|database|user|view)\b",
    r"(?i);\s*(?:insert|update|delete)\s+",
    r"(?i);\s*(?:grant|revoke)\s+",
    r"(?i)\b(?:select|insert|update|delete|create|alter|drop)\s+.{1,50}\s+(?:from|into|table|set|where)\b",
    r"(?i)\b(?:select)\s+.{1,100}\s+from\s+",
    r"(?i)\binsert\s+into\s+\w+",
    r"(?i)\bdelete\s+from\s+\w+",
    r"(?i)\bupdate\s+\w+\s+set\b",
    r"(?i)\b(?:or|and)\s+(?:1\s*[=<>]\s*1|true|false)\b",
    r"(?i)\b(?:or|and)\s+\d+\s*[=<>]\s*\d+",
    r"""(?i)\b(?:or|and)\s+['"][^'"]*['"]\s*[=<>]\s*['"][^'"]*['"]""",
    r"(?i)\b(?:or|and)\s+\w+\s*(?:=|<>|!=)\s*\w+",
    r"(?i)\bwaitfor\s+delay\s+",
    r"(?i)\bbenchmark\s*\(\s*\d+",
    r"(?i)\bsleep\s*\(\s*\d+",
    r"(?i)\bpg_sleep\s*\(\s*\d+",
    r"(?i)\bdbms_lock\.sleep\s*\(",
    r"(?i)\b(?:exec|execute|sp_executesql)\s*\(",
    r"(?i)\b(?:exec|execute)\s+(?:sp_|xp_)\w+",
    r"(?i)\bxp_(?:cmdshell|regread|regwrite|dirtree|fileexist)",
    r"(?i)\bsp_(?:oacreate|oamethod|oadestroy|makewebtask)",
    r"(?i)\b(?:openrowset|opendatasource)\s*\(",
    r"(?i)\binformation_schema\.(?:tables|columns|schemata|routines)\b",
    r"(?i)\bsys(?:objects|tables|columns|databases|schemas)\b",
    r"(?i)\bmysql\.(?:user|db|tables_priv|columns_priv)\b",
    r"(?i)\bpg_(?:tables|database|user|shadow)\b",
    r"(?i)\bsqlite_(?:master|temp_master)\b",
    r"""(?i)\bload_file\s*\(\s*['"][^'"]+['"]\s*\)""",
    r"""(?i)\binto\s+(?:outfile|dumpfile)\s+['"][^'"]+['"]""",
    r"(?i)\bselect\s+.+\s+into\s+outfile\b",
    r"(?i)\b(?:char|chr)\s*\(\s*\d+(?:\s*,\s*\d+)*\s*\)",
    r"(?i)\bconcat\s*\(\s*.+\s*\)",
    r"(?i)\bsubstring\s*\(\s*.+,\s*\d+(?:\s*,\s*\d+)?\s*\)",
    r"(?i)\b(?:ascii|ord)\s*\(\s*.+\s*\)",
    r"(?i)\b(?:hex|unhex|bin)\s*\(\s*.+\s*\)",
    r"(?i)\blength\s*\(\s*.+\s*\)\s*[<>=]",
    r"(?i)\bcast\s*\(\s*.+\s+as\s+\w+\s*\)",
    r"(?i)\bconvert\s*\(\s*.+\s*,\s*\w+\s*\)",
    r"(?i)\bextractvalue\s*\(\s*.+\s*,\s*.+\s*\)",
    r"(?i)\bupdatexml\s*\(\s*.+\s*,\s*.+\s*,\s*.+\s*\)",
    r"(?i)\bexp\s*\(\s*~\s*\(",
    r"(?i)/\*!?\d*\s*\*/",
    r"(?i)--\s*[+-]",
    r"(?i);\s*--",
    r"(?i)\|\|",
    r"(?i)0x[0-9a-fA-F]+",
    r"(?i)\bchar\s*\(\s*0x[0-9a-fA-F]+\s*\)",
    r"(?i)\bwith\s+\w+\s+as\s*\(",
    r"(?i)\bcursor\s+\w+\s+is\b",
    r"(?i)\bfor\s+xml\s+(?:path|raw|auto)\b",
    r"(?i)\bpivot\s*\(",
    r"(?i)\bunpivot\s*\(",
    r"(?i)\bdual\b",
    r"(?i)\bsys\.(?:user_tables|all_tables|dba_tables)\b",
    r"(?i)\butl_(?:file|http|tcp|smtp)",
    r"(?i)\b@@(?:version|servername|identity|rowcount)\b",
    r"(?i)\bhas_dbaccess\s*\(",
    r"(?i)\bversion\s*\(\s*\)",
    r"(?i)\buser\s*\(\s*\)",
    r"(?i)\bdatabase\s*\(\s*\)",
    r"(?i)\bcurrent_(?:database|user|schema)\b",
    r"(?i)\bpg_(?:read_file|ls_dir|stat_file)",
)


@lru_cache(maxsize=1)
def _patterns() -> list[re.Pattern[str]]:
    return [re.compile(src) for src in _SOURCES]


def sql_injection() -> Rivet:
    def handler(context: ChainmailContext, nxt: NextFn) -> ChainmailResult:
        for pattern in _patterns():
            if pattern.search(context.sanitized):
                context.flags.add(SecurityFlags.SQL_INJECTION)
                apply_threat_penalty(context, ThreatLevel.CRITICAL)
                context.metadata["sql_pattern"] = pattern.pattern
                break
        return nxt(context)

    return FnRivet("sql_injection", handler)
