use crate::store::Event;
use serde::Serialize;
use serde_json::Value;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Off,
    Heuristic,
    WitrBridge,
    OpenhumanBridge,
    Hybrid,
}

#[derive(Debug, Serialize)]
pub struct WhyExplanation {
    pub manager: String,
    pub mode: String,
    pub confidence: f32,
    pub target: String,
    pub question: String,
    pub narrative: String,
    pub source_chain: Vec<String>,
    pub actions: Vec<String>,
    pub warnings: Vec<String>,
    pub evidence: Value,
}

fn parse_mode() -> Mode {
    match std::env::var("BASTION_AI_MANAGER_MODE")
        .unwrap_or_else(|_| "hybrid".to_string())
        .to_lowercase()
        .as_str()
    {
        "off" => Mode::Off,
        "heuristic" => Mode::Heuristic,
        "witr" | "witr_bridge" => Mode::WitrBridge,
        "openhuman" | "openhuman_bridge" => Mode::OpenhumanBridge,
        _ => Mode::Hybrid,
    }
}

fn parse_details(ev: &Event) -> Value {
    serde_json::from_str(&ev.details_json).unwrap_or_else(|_| serde_json::json!({}))
}

fn str_field(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string()
}

fn u64_field(v: &Value, key: &str) -> Option<u64> {
    v.get(key).and_then(Value::as_u64)
}

fn build_heuristic(ev: &Event, d: &Value) -> WhyExplanation {
    let pid = u64_field(d, "pid");
    let path = str_field(d, "path");
    let exe = str_field(d, "exe");
    let parent = str_field(d, "parent");
    let source = ev.source.clone();
    let kind = ev.kind.clone();

    let target = if let Some(p) = pid {
        format!("pid {p}")
    } else if !path.is_empty() {
        path.clone()
    } else if !exe.is_empty() {
        exe.clone()
    } else {
        format!("{source}/{kind}")
    };

    let mut chain = Vec::new();
    chain.push(format!("event: {source}/{kind}"));
    if !parent.is_empty() {
        chain.push(format!("parent: {parent}"));
    }
    if !exe.is_empty() {
        chain.push(format!("process: {exe}"));
    }
    if !path.is_empty() {
        chain.push(format!("object: {path}"));
    }

    let mut actions = Vec::new();
    if ev.severity == "alert" {
        actions.push("triage immediately and preserve forensic context".to_string());
    }
    if source == "proc_fp" {
        actions.push("if expected, trust fp/exe to suppress future noise".to_string());
        actions.push("if unexpected, inspect parent process and command line".to_string());
    }
    if source == "fim" && !path.is_empty() {
        actions.push("compare file hash to known-good baseline".to_string());
        actions.push("quarantine the modified file if provenance is unknown".to_string());
    }
    if source == "canary" {
        actions.push("investigate process list around canary touch timestamp".to_string());
    }
    if source == "dns" {
        actions.push("isolate host network path and inspect outbound destinations".to_string());
    }

    let mut warnings = Vec::new();
    if source == "proc_fp" {
        warnings.push("proc fingerprint novelty can include benign browser arg churn".to_string());
    }
    if source == "fim" && path.to_lowercase().contains("hosts") {
        warnings.push("hosts-file tamper is high confidence for DNS hijack attempts".to_string());
    }

    let narrative = format!(
        "{summary}. This exists because bastion observed a {source}/{kind} signal and chained it to {target}.",
        summary = ev.summary,
        source = source,
        kind = kind,
        target = target
    );

    WhyExplanation {
        manager: "bastion-ai-manager".to_string(),
        mode: "heuristic".to_string(),
        confidence: if ev.severity == "alert" { 0.86 } else { 0.68 },
        target,
        question: "why is this running / happening?".to_string(),
        narrative,
        source_chain: chain,
        actions,
        warnings,
        evidence: d.clone(),
    }
}

async fn witr_augment(mut why: WhyExplanation, d: &Value) -> WhyExplanation {
    let Some(pid) = u64_field(d, "pid") else {
        why.warnings
            .push("witr bridge skipped: no pid in event details".to_string());
        return why;
    };

    let cmd = tokio::process::Command::new("witr")
        .args(["--pid", &pid.to_string(), "--short"])
        .output();

    let out = tokio::time::timeout(Duration::from_secs(2), cmd).await;
    match out {
        Ok(Ok(output)) if output.status.success() => {
            let line = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !line.is_empty() {
                why.mode = "heuristic+witr".to_string();
                why.confidence = (why.confidence + 0.08).min(0.99);
                why.source_chain.push(format!("witr: {line}"));
                why.narrative = format!(
                    "{} Causal chain (witr): {}",
                    why.narrative,
                    line
                );
            }
        }
        Ok(Ok(output)) => {
            let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if !err.is_empty() {
                why.warnings.push(format!("witr bridge failed: {err}"));
            } else {
                why.warnings
                    .push("witr bridge failed: non-zero exit code".to_string());
            }
        }
        Ok(Err(e)) => why.warnings.push(format!("witr bridge error: {e}")),
        Err(_) => why
            .warnings
            .push("witr bridge timed out after 2s".to_string()),
    }

    why
}

async fn openhuman_augment(mut why: WhyExplanation, ev: &Event, d: &Value) -> WhyExplanation {
    let base = std::env::var("BASTION_OPENHUMAN_URL").unwrap_or_default();
    if base.trim().is_empty() {
        why.warnings
            .push("openhuman bridge skipped: BASTION_OPENHUMAN_URL not set".to_string());
        return why;
    }

    let url = format!("{}/api/bastion/why", base.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let req = client
        .post(url)
        .json(&serde_json::json!({
            "question": "why is this running / happening?",
            "event": {
                "id": ev.id,
                "ts": ev.ts,
                "source": ev.source,
                "severity": ev.severity,
                "kind": ev.kind,
                "summary": ev.summary,
                "details": d,
            }
        }))
        .send();

    let resp = tokio::time::timeout(Duration::from_secs(3), req).await;
    match resp {
        Ok(Ok(r)) if r.status().is_success() => {
            let json = r.json::<Value>().await.unwrap_or_else(|_| serde_json::json!({}));
            if let Some(text) = json.get("narrative").and_then(Value::as_str) {
                why.mode = "heuristic+openhuman".to_string();
                why.confidence = (why.confidence + 0.06).min(0.99);
                why.narrative = text.to_string();
            }
            if let Some(actions) = json.get("actions").and_then(Value::as_array) {
                let merged: Vec<String> = actions
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect();
                if !merged.is_empty() {
                    why.actions = merged;
                }
            }
        }
        Ok(Ok(r)) => why
            .warnings
            .push(format!("openhuman bridge HTTP {}", r.status())),
        Ok(Err(e)) => why.warnings.push(format!("openhuman bridge error: {e}")),
        Err(_) => why
            .warnings
            .push("openhuman bridge timed out after 3s".to_string()),
    }

    why
}

pub async fn explain_event(ev: &Event) -> WhyExplanation {
    let mode = parse_mode();
    let details = parse_details(ev);

    if mode == Mode::Off {
        return WhyExplanation {
            manager: "bastion-ai-manager".to_string(),
            mode: "off".to_string(),
            confidence: 0.0,
            target: format!("{}/{}", ev.source, ev.kind),
            question: "why is this running / happening?".to_string(),
            narrative: "AI manager is disabled (BASTION_AI_MANAGER_MODE=off).".to_string(),
            source_chain: vec![],
            actions: vec![],
            warnings: vec![],
            evidence: details,
        };
    }

    let mut why = build_heuristic(ev, &details);
    match mode {
        Mode::Heuristic => why,
        Mode::WitrBridge => witr_augment(why, &details).await,
        Mode::OpenhumanBridge => openhuman_augment(why, ev, &details).await,
        Mode::Hybrid => {
            why = witr_augment(why, &details).await;
            openhuman_augment(why, ev, &details).await
        }
        Mode::Off => unreachable!(),
    }
}
