# language: Python 3, file: pipeline.py
# Adaptive multi-stage pipeline — static → protectors → deobf → dynamic optional
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .artifact import ArtifactProfile, LangFamily, classify_artifact


@dataclass
class StageResult:
    name: str
    ok: bool
    duration_ms: float
    data: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


@dataclass
class PipelineResult:
    profile: ArtifactProfile
    stages: list[StageResult]
    output_dir: str
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile.to_dict(),
            "stages": [
                {
                    "name": s.name,
                    "ok": s.ok,
                    "duration_ms": s.duration_ms,
                    "data": s.data,
                    "errors": s.errors,
                }
                for s in self.stages
            ],
            "output_dir": self.output_dir,
            "summary": self.summary,
        }

    def write_json(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")


class Pipeline:
    """Language-agnostic orchestration. Stages register by predicate on ArtifactProfile."""

    def __init__(self, output_dir: str | Path | None = None):
        self.output_dir = Path(output_dir or "output/run")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._stages: list[tuple[str, Callable[[ArtifactProfile, Path], dict[str, Any]], Callable[[ArtifactProfile], bool]]] = []

    def add(
        self,
        name: str,
        fn: Callable[[ArtifactProfile, Path], dict[str, Any]],
        when: Callable[[ArtifactProfile], bool] | None = None,
    ) -> "Pipeline":
        pred = when or (lambda _p: True)
        self._stages.append((name, fn, pred))
        return self

    def run(self, target: str | Path, dynamic: bool = False) -> PipelineResult:
        profile = classify_artifact(target)
        stages: list[StageResult] = []
        out = self.output_dir / f"{Path(target).stem}_{profile.sha256[:12]}"
        out.mkdir(parents=True, exist_ok=True)
        (out / "profile.json").write_text(json.dumps(profile.to_dict(), indent=2), encoding="utf-8")

        for name, fn, pred in self._stages:
            if name.startswith("dynamic.") and not dynamic:
                continue
            if not pred(profile):
                stages.append(StageResult(name, True, 0.0, {"skipped": True}))
                continue
            t0 = time.perf_counter()
            try:
                data = fn(profile, out) or {}
                stages.append(StageResult(name, True, (time.perf_counter() - t0) * 1000, data))
            except Exception as e:  # stage isolation — never abort whole pipeline
                stages.append(
                    StageResult(name, False, (time.perf_counter() - t0) * 1000, {}, [f"{type(e).__name__}: {e}"])
                )

        summary = {
            "family": profile.family.value,
            "arch": profile.arch.value,
            "protectors": [p.get("name") for p in profile.protector_candidates],
            "stages_ok": sum(1 for s in stages if s.ok),
            "stages_fail": sum(1 for s in stages if not s.ok),
            "dynamic": dynamic,
        }
        result = PipelineResult(profile, stages, str(out), summary)
        result.write_json(out / "pipeline_result.json")
        return result


def default_family_gate(*families: LangFamily) -> Callable[[ArtifactProfile], bool]:
    want = set(families)

    def _p(profile: ArtifactProfile) -> bool:
        return profile.family in want or profile.family == LangFamily.MIXED

    return _p
