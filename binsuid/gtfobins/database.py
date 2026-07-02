from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any

from binsuid.models import PRIVESC_FUNCTIONS, Technique, VectorType
from binsuid.utils import capability_matches, executable_aliases


class GTFOBinsDatabase:
    def __init__(self, data: dict[str, Any]):
        self.data = data
        self.functions_meta = data.get("functions", {})
        self.contexts_meta = data.get("contexts", {})
        self.executables = data.get("executables", {})

    @classmethod
    def load(cls, path: Path | None = None) -> "GTFOBinsDatabase":
        if path is not None:
            with path.open(encoding="utf-8") as handle:
                return cls(json.load(handle))

        package_data = resources.files("binsuid").joinpath("data/gtfobins-api.json")
        with package_data.open(encoding="utf-8") as handle:
            return cls(json.load(handle))

    def resolve_executable(self, path: str) -> str | None:
        for alias in executable_aliases(path):
            if alias in self.executables:
                return alias
        return None

    def techniques_for(
        self,
        path: str,
        vector: VectorType,
        *,
        present_caps: list[str] | None = None,
        privesc_only: bool = True,
    ) -> list[Technique]:
        key = self.resolve_executable(path)
        if not key:
            return []

        context = vector.value
        entry = self.executables[key]
        techniques: list[Technique] = []

        for function_name, items in entry.get("functions", {}).items():
            if privesc_only and function_name not in PRIVESC_FUNCTIONS:
                continue
            for item in items:
                contexts = item.get("contexts", {})
                if context not in contexts:
                    continue

                ctx_data = contexts[context]
                cap_requirements: list[str] = []
                if vector == VectorType.CAPABILITIES and isinstance(ctx_data, dict):
                    cap_requirements = [c.upper() for c in ctx_data.get("list", [])]
                    if cap_requirements and present_caps is not None:
                        if not capability_matches(cap_requirements, present_caps):
                            continue

                code = item.get("code", "")
                if isinstance(ctx_data, dict) and ctx_data.get("code"):
                    code = ctx_data["code"]

                meta = self.functions_meta.get(function_name, {})
                description = meta.get("description", "")
                if isinstance(ctx_data, dict):
                    metadata = dict(ctx_data)
                elif ctx_data is None:
                    metadata = {}
                else:
                    metadata = {"raw": ctx_data}

                techniques.append(
                    Technique(
                        executable=key,
                        function=function_name,
                        code=code,
                        context=context,
                        description=description,
                        capability_requirements=cap_requirements,
                        metadata=metadata,
                        gtfobins_url=f"https://gtfobins.org/{key}/#{function_name}",
                    )
                )

        return _sort_techniques(techniques)

    def list_known_executables(self) -> list[str]:
        return sorted(self.executables.keys())


def _sort_techniques(techniques: list[Technique]) -> list[Technique]:
    priority = {name: idx for idx, name in enumerate(PRIVESC_FUNCTIONS)}

    def sort_key(tech: Technique) -> tuple[int, str]:
        return (priority.get(tech.function, 99), tech.function)

    return sorted(techniques, key=sort_key)


def enrich_findings(findings: list, database: GTFOBinsDatabase) -> None:
    for finding in findings:
        finding.techniques = database.techniques_for(
            finding.path,
            finding.vector,
            present_caps=finding.capabilities,
        )
