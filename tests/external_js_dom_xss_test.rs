//! End-to-end coverage for issue #1094: fetch and AST-analyze external
//! `<script src>` bundles for DOM-XSS.
//!
//! Two cases, each backed by a real local Axum server:
//!
//! 1. `external_js_dom_xss_detected` — flag **on**: scanner fetches
//!    `/ext.js`, runs AST taint analysis, reports a finding whose evidence
//!    contains `[external: …]` and whose request counter shows ≥ 1 fetch.
//!
//! 2. `external_js_off_makes_no_request` — flag **off**: `/ext.js` is never
//!    requested (counter stays 0) and no `[external:]` evidence appears.

use axum::Router;
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use dalfox::cmd::scan::{ScanArgs, run_scan};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpListener;

/// Reflects `q` into a plain div (gives the scanner a param to discover)
/// and loads an external script with a DOM-XSS sink.
async fn page_handler(Query(p): Query<HashMap<String, String>>) -> Html<String> {
    let q = p.get("q").cloned().unwrap_or_default();
    Html(format!(
        r#"<html><body><div id="out">{q}</div><script src="/ext.js"></script></body></html>"#
    ))
}

/// External bundle: `location.hash` → `innerHTML` taint path.
async fn ext_js_handler(State(counter): State<Arc<AtomicUsize>>) -> impl IntoResponse {
    counter.fetch_add(1, Ordering::SeqCst);
    (
        [(header::CONTENT_TYPE, "application/javascript")],
        r#"document.getElementById('out').innerHTML = location.hash;"#,
    )
}

fn make_args(url: String, out: String, analyze_external_js: bool) -> ScanArgs {
    ScanArgs {
        detect_outdated_libs: false,
        analyze_external_js,
        input_type: "url".to_string(),
        format: "json".to_string(),
        targets: vec![url],
        param: vec![],
        data: None,
        headers: vec![],
        cookies: vec![],
        method: "GET".to_string(),
        user_agent: None,
        cookie_from_raw: None,
        include_url: vec![],
        exclude_url: vec![],
        ignore_param: vec![],
        out_of_scope: vec![],
        out_of_scope_file: None,
        mining_dict_word: None,
        skip_mining: true,
        skip_mining_dict: true,
        skip_mining_dom: true,
        only_discovery: false,
        skip_discovery: false,
        skip_reflection_header: true,
        skip_reflection_cookie: true,
        skip_reflection_path: true,
        timeout: 5,
        scan_timeout: 0,
        delay: 0,
        proxy: None,
        follow_redirects: false,
        ignore_return: vec![],
        output: Some(out),
        include_request: false,
        include_response: false,
        include_all: false,
        no_color: true,
        silence: true,
        dry_run: false,
        stream_findings: false,
        poc_type: "plain".to_string(),
        limit: None,
        limit_result_type: "all".to_string(),
        only_poc: vec![],
        workers: 4,
        max_concurrent_targets: 4,
        max_targets_per_host: 100,
        encoders: vec!["url".to_string(), "html".to_string()],
        custom_blind_xss_payload: None,
        blind_callback_url: None,
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),
        skip_xss_scanning: false,
        max_payloads_per_param: 0,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 1,
        skip_ast_analysis: false,
        hpp: false,
        waf_bypass: "off".to_string(),
        skip_waf_probe: true,
        force_waf: None,
        waf_evasion: false,
        waf_min_confidence: 0.0,
        remote_payloads: vec![],
        remote_wordlists: vec![],
    }
}

/// With `--analyze-external-js`: the scanner must fetch `/ext.js` (counter ≥ 1)
/// and report at least one finding with `[external: …]` in its evidence.
#[tokio::test]
async fn external_js_dom_xss_detected() {
    dalfox::ensure_crypto_provider();

    let counter = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/", get(page_handler))
        .route("/ext.js", get(ext_js_handler))
        .with_state(counter.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let url = format!("http://127.0.0.1:{}/?q=seed", addr.port());
    let out = std::env::temp_dir().join(format!("dlfx_extjs_on_{}.json", addr.port()));
    run_scan(&make_args(url, out.to_string_lossy().to_string(), true)).await;

    let content = std::fs::read_to_string(&out).expect("scan must write JSON output");
    let _ = std::fs::remove_file(&out);
    let v: serde_json::Value = serde_json::from_str(&content).expect("valid JSON");
    let findings = v["findings"].as_array().cloned().unwrap_or_default();

    assert!(
        counter.load(Ordering::SeqCst) > 0,
        "/ext.js was never fetched — analyze_external_js path did not fire"
    );
    assert!(
        findings.iter().any(|f| f
            .get("evidence")
            .and_then(|e| e.as_str())
            .is_some_and(|e| e.contains("[external:"))),
        "expected a finding with [external: ...] in evidence; got: {findings:#?}"
    );
}

/// Without `--analyze-external-js`: `/ext.js` must never be fetched (counter
/// stays 0) and no `[external:]` evidence may appear.
#[tokio::test]
async fn external_js_off_makes_no_request() {
    dalfox::ensure_crypto_provider();

    let counter = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/", get(page_handler))
        .route("/ext.js", get(ext_js_handler))
        .with_state(counter.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let url = format!("http://127.0.0.1:{}/?q=seed", addr.port());
    let out = std::env::temp_dir().join(format!("dlfx_extjs_off_{}.json", addr.port()));
    run_scan(&make_args(url, out.to_string_lossy().to_string(), false)).await;

    if let Ok(content) = std::fs::read_to_string(&out) {
        let _ = std::fs::remove_file(&out);
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
            let findings = v["findings"].as_array().cloned().unwrap_or_default();
            assert!(
                !findings.iter().any(|f| f
                    .get("evidence")
                    .and_then(|e| e.as_str())
                    .is_some_and(|e| e.contains("[external:"))),
                "flag-off scan must not produce [external:] findings; got: {findings:#?}"
            );
        }
    }

    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "/ext.js must not be fetched when --analyze-external-js is off"
    );
}
