# language: Python 3, file: engine.py
# StreetEngine — wires static, deobf, protectors, dynamic into one pipeline
from __future__ import annotations

from pathlib import Path
from typing import Any

from .artifact import ArtifactProfile, LangFamily, classify_artifact
from .pipeline import Pipeline, PipelineResult, default_family_gate


class StreetEngine:
    """Main entry used by CLI and AI agents. No hardcoded offsets — stages re-derive per sample."""

    def __init__(self, output_root: str | Path = "output"):
        self.output_root = Path(output_root)
        self.output_root.mkdir(parents=True, exist_ok=True)

    def classify(self, target: str | Path) -> ArtifactProfile:
        return classify_artifact(target)

    def build_pipeline(self, run_dir: Path | None = None) -> Pipeline:
        from street_decrepytor.static.analyzer import stage_static_analyze
        from street_decrepytor.static.junk import stage_junk_scan
        from street_decrepytor.static.strings import stage_string_scan
        from street_decrepytor.protectors.detect import stage_protector_detect
        from street_decrepytor.deobf.router import stage_deobf_route
        from street_decrepytor.crypto.recover import stage_crypto_heuristics
        from street_decrepytor.crypto.simd_emu import stage_simd_emu
        from street_decrepytor.multibuild.scan import stage_multibuild
        from street_decrepytor.dynamic.memory import stage_process_scan
        from street_decrepytor.dynamic.antidebug import stage_antidebug_plan
        from street_decrepytor.deobf.csharp.dnfile_bridge import stage_dotnet_bridge
        from street_decrepytor.deobf.java.string_emu import stage_java_string_emu
        from street_decrepytor.deobf.cfg_obfuscation import stage_cfg_obfuscation
        from street_decrepytor.deobf.rust_rt.tauri_extract import stage_tauri_extract

        pipe = Pipeline(run_dir or self.output_root / "run")
        pipe.add("static.analyze", stage_static_analyze)
        pipe.add("static.strings", stage_string_scan)
        pipe.add("static.junk", stage_junk_scan)
        pipe.add("protectors.detect", stage_protector_detect)
        pipe.add("multibuild.scan", stage_multibuild)
        pipe.add("crypto.heuristics", stage_crypto_heuristics)
        pipe.add("crypto.simd_emu", stage_simd_emu)
        pipe.add("deobf.route", stage_deobf_route)
        pipe.add("deobf.dotnet_bridge", stage_dotnet_bridge)
        pipe.add("deobf.java_strings", stage_java_string_emu)
        pipe.add("deobf.cfg", stage_cfg_obfuscation)
        pipe.add(
            "deobf.tauri",
            stage_tauri_extract,
            when=lambda p: p.family in (LangFamily.RUST, LangFamily.NATIVE_PE),
        )


        # static plan always; live attach stays under dynamic.*
        pipe.add("antidebug.plan", stage_antidebug_plan)
        pipe.add(
            "dynamic.process_scan",
            stage_process_scan,
            when=lambda p: p.family
            in (
                LangFamily.NATIVE_PE,
                LangFamily.RUST,
                LangFamily.GO,
                LangFamily.DOTNET,
                LangFamily.MIXED,
                LangFamily.CPP_CLI,
            ),
        )
        return pipe

    def analyze(
        self,
        target: str | Path,
        *,
        dynamic: bool = False,
        out: str | Path | None = None,
    ) -> PipelineResult:
        run_dir = Path(out) if out else self.output_root / "run"
        return self.build_pipeline(run_dir).run(target, dynamic=dynamic)

    def report(self, target: str | Path, **kwargs: Any) -> dict[str, Any]:
        result = self.analyze(target, **kwargs)
        return result.to_dict()
