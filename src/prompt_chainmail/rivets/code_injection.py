from __future__ import annotations

import re
from functools import lru_cache

from prompt_chainmail.rivets.base import FnRivet, NextFn, Rivet
from prompt_chainmail.rivets.types import SecurityFlags, ThreatLevel
from prompt_chainmail.rivets.utils import apply_threat_penalty
from prompt_chainmail.types import ChainmailContext, ChainmailResult

_SOURCES = (
    r"(?i)\b(eval|exec|execfile|compile)\s*\(",
    r"(?i)\b(import\s+os|import\s+subprocess|import\s+sys)\b",
    r"(?i)\b(require\s*\(|module\.exports)\b",
    r"(?i)<script[^>]*>|</script>",
    r"(?i)\b(function\s*\(|=>\s*\{|\$\{)",
    r"(?i)\b(rm\s+-rf|del\s+/|sudo\s+)",
    r"(?i)\b(wget|curl|fetch)\s+http",
    r"(?i)\b(__import__|getattr|setattr|hasattr)\s*\(",
    r"(?i)\b(process\.env|process\.exit|process\.kill)",
    r"(?i)\b(setTimeout|setInterval)\s*\(",
    r"(?i)\bnew\s+Function\s*\(",
    r"(?i)\bimport\s*\(",
    r"(?i)\b(child_process|fs\.unlink|fs\.rmdir)\b",
    r"(?i)\b(sh\s+-c|bash\s+-c|cmd\s+/c|powershell\s+-c)\b",
    r"(?i)\b(system\s*\(|popen\s*\(|shell_exec\s*\()\b",
    r"(?i)\b(os\.system|subprocess\.call|subprocess\.run)\b",
    r"(?i)\b(cat\s+/etc/passwd|ls\s+-la|ps\s+aux|netstat\s+-an)\b",
    r"(?i)\b(whoami|id|uname\s+-a|pwd|env)\b",
    r"(?i)\b(chmod\s+\+x|chown\s+|mount\s+|umount\s+)\b",
    r"(?i)\b(nc\s+-|ncat\s+-|telnet\s+|ssh\s+)\b",
    r"(?i)\b(iptables\s+|firewall\s+|selinux\s+)\b",
    r"(?i)\b(crontab\s+-|at\s+now|systemctl\s+)\b",
    r"(?i)\b(find\s+.*-exec|xargs\s+.*rm|grep\s+-r)\b",
    r"(?i)\b(tar\s+-|zip\s+-|unzip\s+-|gzip\s+-)\b",
    r"(?i)\b(kill\s+-9|killall\s+|pkill\s+)\b",
    r"(?i)\b(nohup\s+|screen\s+-|tmux\s+)\b",
    r"(?i)\b(dd\s+if=|fdisk\s+-|mkfs\s+)\b",
    r"(?i)\b(echo\s+.*>\s*/|cat\s+.*>\s*/)\b",
    r"(?i)\b(\|\s*sh|\|\s*bash|\|\s*zsh)\b",
    r"(?i)\b(`[^`]*`|\$\([^)]*\))\b",
)


@lru_cache(maxsize=1)
def _patterns() -> list[re.Pattern[str]]:
    return [re.compile(src) for src in _SOURCES]


def code_injection() -> Rivet:
    def handler(context: ChainmailContext, nxt: NextFn) -> ChainmailResult:
        for pattern in _patterns():
            if pattern.search(context.sanitized):
                context.flags.add(SecurityFlags.CODE_INJECTION)
                apply_threat_penalty(context, ThreatLevel.CRITICAL)
                context.metadata["code_pattern"] = pattern.pattern
                break
        return nxt(context)

    return FnRivet("code_injection", handler)
