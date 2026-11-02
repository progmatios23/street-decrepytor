//! Encryption / decrypt flow per region — always emitted, even on gaps.

use serde::{Deserialize, Serialize};
use street_crypto::{detect_systems, run_static_bytes, SolvedHit};
use street_lift::{lift_bytes, Abi, LiftOptions};
use street_core::Arch;
use street_core::pe::parse_pe;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStep {
    pub stage: String,
    pub status: String, // ok | gap | skip
    pub detail: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionFlow {
    pub id: String,
    pub system: String,
    pub confidence: f32,
    pub playbook: String,
    pub region_offset: Option<u64>,
    pub region_size: Option<u64>,
    pub steps: Vec<FlowStep>,
    pub stub_pseudocode: Option<String>,
    pub solved: Option<SolvedHit>,
    pub notes: Vec<String>,
}

pub fn build_encryption_flows(path: &Path, data: &[u8], out_dir: &Path) -> Vec<EncryptionFlow> {
    let _ = std::fs::create_dir_all(out_dir.join("flows"));
    let ranking = detect_systems(data);
    let report = run_static_bytes(path, data).ok();
    let mut flows = Vec::new();

    for (i, hit) in ranking.hits.iter().enumerate() {
        let id = format!("enc_{i:03}_{}", hit.system);
        let mut steps = vec![
            FlowStep {
                stage: "detect".into(),
                status: "ok".into(),
                detail: format!("{} conf={:.2}", hit.system, hit.confidence),
                evidence: hit.evidence.clone(),
            },
            FlowStep {
                stage: "rank".into(),
                status: "ok".into(),
                detail: format!("rank_score={:.1} playbook={}", hit.rank_score, ranking.playbook),
                evidence: vec![],
            },
        ];

        // stub pseudocode near first offset if any
        let mut stub_c = None;
        if let Some(&off) = hit.offsets.first() {
            let off = off as usize;
            if off + 32 < data.len() {
                let window = &data[off..data.len().min(off + 0x400)];
                let img = parse_pe(data).ok();
                let arch = img.as_ref().map(|i| i.arch).unwrap_or(Arch::X64);
                let base = img
                    .as_ref()
                    .and_then(|im| {
                        // approximate VA for file off
                        for s in &im.sections {
                            let start = s.raw_off as usize;
                            let end = start + s.raw_size as usize;
                            if off >= start && off < end {
                                return Some(im.image_base + s.va as u64 + (off - start) as u64);
                            }
                        }
                        None
                    })
                    .unwrap_or(off as u64);
                let lift = lift_bytes(
                    window,
                    base,
                    arch,
                    &format!("decrypt_stub_{}", hit.system),
                    &LiftOptions {
                        abi: Abi::Win64,
                        asm_comments: true,
                        max_insns: 128,
                    },
                );
                stub_c = Some(lift.c.clone());
                let _ = std::fs::write(
                    out_dir
                        .join("flows")
                        .join(format!("{id}_stub.c")),
                    &lift.c,
                );
                steps.push(FlowStep {
                    stage: "stub_pseudocode".into(),
                    status: if lift.insn_count > 0 { "ok" } else { "gap" }.into(),
                    detail: format!("lifted {} insns near {:#x}", lift.insn_count, off),
                    evidence: lift.notes,
                });
            }
        } else {
            steps.push(FlowStep {
                stage: "stub_pseudocode".into(),
                status: "gap".into(),
                detail: "no offset for stub window".into(),
                evidence: vec![],
            });
        }

        let solved = report
            .as_ref()
            .and_then(|r| r.solved.iter().find(|s| s.cipher.contains(&hit.system) || hit.system.contains(&s.cipher) || (hit.system == "dw_stub" && s.cipher == "dw_stub") || (hit.system.starts_with("xor") && s.cipher.contains("xor"))))
            .cloned();

        if let Some(ref s) = solved {
            steps.push(FlowStep {
                stage: "auto_solve".into(),
                status: if s.decrypted { "ok" } else { "gap" }.into(),
                detail: format!(
                    "{} magic={} score={} off={:#x}",
                    s.cipher, s.magic, s.score, s.offset
                ),
                evidence: vec![s.note.clone()],
            });
            steps.push(FlowStep {
                stage: "verify".into(),
                status: if s.decrypted { "ok" } else { "gap" }.into(),
                detail: if s.decrypted {
                    "transform kind=cipher recorded".into()
                } else {
                    "not promoted to decrypted".into()
                },
                evidence: vec![],
            });
        } else {
            steps.push(FlowStep {
                stage: "auto_solve".into(),
                status: "gap".into(),
                detail: "no matching solved hit — shapes only or needs live dump".into(),
                evidence: vec![],
            });
            steps.push(FlowStep {
                stage: "verify".into(),
                status: "skip".into(),
                detail: "nothing to verify".into(),
                evidence: vec![],
            });
        }

        // playbook reminder as final step
        steps.push(FlowStep {
            stage: "playbook".into(),
            status: "ok".into(),
            detail: ranking.playbook.clone(),
            evidence: report
                .as_ref()
                .map(|r| r.playbook_steps.clone())
                .unwrap_or_default(),
        });

        let flow = EncryptionFlow {
            id: id.clone(),
            system: hit.system.clone(),
            confidence: hit.confidence,
            playbook: ranking.playbook.clone(),
            region_offset: hit.offsets.first().copied(),
            region_size: None,
            steps,
            stub_pseudocode: stub_c,
            solved,
            notes: vec![
                "Flow is always written — gaps are explicit, never silent.".into(),
            ],
        };
        let _ = std::fs::write(
            out_dir.join("flows").join(format!("{id}.json")),
            serde_json::to_vec_pretty(&flow).unwrap_or_default(),
        );
        flows.push(flow);
    }

    if flows.is_empty() {
        let gap = EncryptionFlow {
            id: "enc_000_none".into(),
            system: "none".into(),
            confidence: 0.0,
            playbook: "generic".into(),
            region_offset: None,
            region_size: None,
            steps: vec![FlowStep {
                stage: "detect".into(),
                status: "gap".into(),
                detail: "no crypto systems ranked".into(),
                evidence: vec![],
            }],
            stub_pseudocode: None,
            solved: None,
            notes: vec!["clean or unrecognized — see extract/inventory".into()],
        };
        let _ = std::fs::write(
            out_dir.join("flows").join("enc_000_none.json"),
            serde_json::to_vec_pretty(&gap).unwrap_or_default(),
        );
        flows.push(gap);
    }

    let _ = std::fs::write(
        out_dir.join("ENCRYPTION_FLOWS.json"),
        serde_json::to_vec_pretty(&flows).unwrap_or_default(),
    );
    flows
}
