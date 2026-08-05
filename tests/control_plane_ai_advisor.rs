mod support;

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use bearust::ai_advisor::{
    build_workflow_prompt, validate_workflow_output, AdvisorErrorCode, AdvisorJobId,
    AdvisorJobStatus, AdvisorRequest, AdvisorWorkflow, AiAdvisorService, ConfigurationDraft,
    DraftAction, DraftWafMode, RedactedValue, Redactor, MAX_ADVISOR_COMMAND_BYTES,
};
use bearust::ai_advisor_provider::{
    ChatChoice, ChatCompletionRequest, ChatCompletionResponse, ChatMessage, LlmProvider,
    ProviderError,
};
use bearust::control_plane::models::{WafAction, WafMode, WafRule};
use bearust::control_plane::{auth, build_state, router, AppState};
use bearust::control_plane::{rbac::Permission, repository};
use chrono::{Duration, Utc};
use futures_util::FutureExt;
use http_body_util::BodyExt;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use tower::ServiceExt;

async fn pool() -> repository::DbPool {
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&pool).await.unwrap();
    pool
}

fn redacted(value: &str) -> RedactedValue {
    Redactor::default().redact(&serde_json::from_str(value).unwrap())
}

#[test]
fn workflow_prompts_are_bounded_redacted_and_outputs_are_strictly_typed() {
    let snapshot = Redactor::with_secret_keys(["tenant_secret"]).redact(&serde_json::json!({
        "summary": "tenant_secret=do-not-send; client=192.0.2.10",
        "count": 7,
    }));
    for workflow in [
        AdvisorWorkflow::IncidentExplanation,
        AdvisorWorkflow::SecuritySummary,
        AdvisorWorkflow::RuleTuning,
        AdvisorWorkflow::ConfigurationDraft,
    ] {
        let prompt = build_workflow_prompt(workflow, &snapshot, "id").unwrap();
        assert!(prompt.len() <= MAX_ADVISOR_COMMAND_BYTES);
        assert!(prompt.contains("locale=id"));
        assert!(!prompt.contains("do-not-send"));
        assert!(!prompt.contains("192.0.2.10"));
    }

    let valid = r#"{"workflow":"incident_explanation","summary":"Blocked request pattern","severity":"warning","signals":["waf block spike"],"reason_ids":["rule-7"],"score":82}"#;
    let insight = validate_workflow_output(AdvisorWorkflow::IncidentExplanation, valid).unwrap();
    assert_eq!(insight.value()["score"], 82);
    let unknown = r#"{"workflow":"incident_explanation","summary":"safe","severity":"warning","signals":[],"reason_ids":[],"score":50,"raw_provider_body":"secret"}"#;
    assert_eq!(
        validate_workflow_output(AdvisorWorkflow::IncidentExplanation, unknown),
        Err(AdvisorErrorCode::InvalidResponse)
    );
    assert_eq!(
        validate_workflow_output(AdvisorWorkflow::SecuritySummary, valid),
        Err(AdvisorErrorCode::InvalidResponse)
    );
    let draft = r#"{"workflow":"configuration_draft","summary":"Enable blocking mode","action":"set_waf_mode","mode":"block","expected_config_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    let draft = validate_workflow_output(AdvisorWorkflow::ConfigurationDraft, draft).unwrap();
    assert_eq!(draft.value()["action"], "set_waf_mode");
    assert_eq!(draft.value()["mode"], "block");
}

struct SchemaProvider(&'static str);

#[async_trait]
impl LlmProvider for SchemaProvider {
    async fn complete(
        &self,
        _: ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, ProviderError> {
        Ok(ChatCompletionResponse {
            id: "provider-response".into(),
            choices: vec![ChatChoice {
                message: ChatMessage {
                    content: self.0.into(),
                },
            }],
        })
    }
}

fn enabled_service(provider_output: &'static str) -> AiAdvisorService {
    AiAdvisorService::from_env_with(|name| match name {
        "LLM_API_URL" => Some("https://llm.example.test".into()),
        "LLM_API_KEY" => Some("key".into()),
        _ => None,
    })
    .unwrap()
    .with_provider(Arc::new(SchemaProvider(provider_output)), 4, 1)
}

async fn terminal_response(
    service: &AiAdvisorService,
    id: &AdvisorJobId,
) -> bearust::ai_advisor::AdvisorResponse {
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if let Some(response) = service.result(id) {
                if matches!(
                    response.status,
                    AdvisorJobStatus::Completed | AdvisorJobStatus::Failed
                ) {
                    break response;
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}

async fn api_state(service: AiAdvisorService) -> (axum::Router, AppState, String, String, String) {
    let directory = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let mut state = build_state("sqlite::memory:", directory.path(), "setup-token")
        .await
        .unwrap();
    let admin = repository::insert_user(&state.db, "admin@advisor.test", "hash", "admin")
        .await
        .unwrap();
    let operator = repository::insert_user(&state.db, "operator@advisor.test", "hash", "operator")
        .await
        .unwrap();
    let viewer = repository::insert_user(&state.db, "viewer@advisor.test", "hash", "viewer")
        .await
        .unwrap();
    let expires = "2999-01-01T00:00:00Z";
    for (user, token) in [
        (&admin, "admin-token"),
        (&operator, "operator-token"),
        (&viewer, "viewer-token"),
    ] {
        repository::create_session(&state.db, user.id, &auth::token_hash(token), expires)
            .await
            .unwrap();
    }
    state.ai_advisor = Arc::new(service);
    (
        router(state.clone()),
        state,
        "bearust_session=admin-token".into(),
        "bearust_session=operator-token".into(),
        "bearust_session=viewer-token".into(),
    )
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

#[tokio::test]
async fn advisor_api_authenticates_authorizes_redacts_and_publishes_queued_jobs() {
    let (disabled, _, admin, _, viewer) = api_state(AiAdvisorService::disabled()).await;
    let unauthenticated = disabled
        .clone()
        .oneshot(
            Request::get("/api/ai-advisor/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    let status = disabled
        .clone()
        .oneshot(
            Request::get("/api/ai-advisor/status")
                .header("cookie", viewer)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    assert_eq!(
        json_body(status).await,
        serde_json::json!({"enabled": false})
    );
    let unavailable = disabled
        .oneshot(
            Request::post("/api/ai-advisor/analyses")
                .header("cookie", admin)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"workflow":"security_summary"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json_body(unavailable).await["code"], "advisor_disabled");

    let provider = r#"{"workflow":"security_summary","summary":"Safe summary","severity":"info","signals":[],"reason_ids":[],"score":70}"#;
    let (app, state, _, operator, viewer) = api_state(enabled_service(provider)).await;
    let denied = app
        .clone()
        .oneshot(
            Request::post("/api/ai-advisor/analyses")
                .header("cookie", &viewer)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"workflow":"security_summary"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let unknown = app
        .clone()
        .oneshot(
            Request::post("/api/ai-advisor/analyses")
                .header("cookie", &operator)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"workflow":"security_summary","provider_body":"forbidden"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(unknown).await["code"], "advisor_invalid_request");

    let mut events = state.realtime.subscribe();
    let accepted = app
        .clone()
        .oneshot(
            Request::post("/api/ai-advisor/analyses")
                .header("cookie", &operator)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"workflow":"security_summary","command":"password=hunter2 client=192.0.2.10"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    let accepted = json_body(accepted).await;
    assert_eq!(accepted["status"], "queued");
    assert!(accepted["job_id"].as_str().is_some());
    assert_eq!(events.recv().await.unwrap().kind, "audit");
    assert_eq!(events.recv().await.unwrap().kind, "ai_advisor.changed");

    let insights = app
        .oneshot(
            Request::get("/api/ai-advisor/insights?page=1&page_size=10")
                .header("cookie", &operator)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(insights.status(), StatusCode::OK);
    let insights = json_body(insights).await;
    let serialized = insights.to_string();
    assert_eq!(insights["total"], 1);
    assert!(!serialized.contains("hunter2"));
    assert!(!serialized.contains("192.0.2.10"));

    let audit_details: Vec<String> = sqlx::query_scalar(
        "SELECT details FROM audit_logs WHERE event LIKE 'ai_advisor_%' ORDER BY created_at",
    )
    .fetch_all(&state.db)
    .await
    .unwrap();
    assert!(!audit_details.is_empty());
    assert!(!audit_details.join(";").contains("hunter2"));
}

async fn completed_waf_draft(
    state: &AppState,
    owner_id: i64,
    mode: DraftWafMode,
    expected_hash: Option<String>,
) -> AdvisorJobId {
    let config = repository::get_waf_config(&state.db).await.unwrap();
    let config_hash = bearust::control_plane::ai_advisor::waf_config_hash(&config);
    let draft = ConfigurationDraft {
        workflow: AdvisorWorkflow::ConfigurationDraft,
        summary: "Change WAF mode".into(),
        action: DraftAction::SetWafMode,
        mode,
        expected_config_hash: expected_hash.unwrap_or_else(|| config_hash.clone()),
    };
    let sealed = validate_workflow_output(
        AdvisorWorkflow::ConfigurationDraft,
        &serde_json::to_string(&draft).unwrap(),
    )
    .unwrap();
    let id = AdvisorJobId::new();
    let record = repository::insert_advisor_job(
        &state.db,
        &repository::NewAdvisorJob {
            job_id: id.clone(),
            owner_id,
            workflow: AdvisorWorkflow::ConfigurationDraft,
            redacted_input: redacted(r#"{"message":"safe"}"#),
            provider_model: "test-model".into(),
            config_version: config.updated_at,
            config_hash,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
        },
    )
    .await
    .unwrap();
    assert!(
        repository::claim_advisor_job(&state.db, &record.job_id, Utc::now())
            .await
            .unwrap()
    );
    assert!(repository::finish_advisor_job(
        &state.db,
        &record.job_id,
        AdvisorJobStatus::Completed,
        Some(&sealed),
        None,
        Utc::now(),
    )
    .await
    .unwrap());
    id
}

#[tokio::test]
async fn advisor_draft_approval_is_admin_stale_safe_guarded_and_audited() {
    let provider = r#"{"workflow":"security_summary","summary":"Safe","severity":"info","signals":[],"reason_ids":[],"score":70}"#;
    let (app, state, admin, operator, _) = api_state(enabled_service(provider)).await;
    let admin_id = repository::find_user(&state.db, "admin@advisor.test")
        .await
        .unwrap()
        .unwrap()
        .0
        .id;

    let denied_id = completed_waf_draft(&state, admin_id, DraftWafMode::Block, None).await;
    let denied = app
        .clone()
        .oneshot(
            Request::post(format!("/api/ai-advisor/drafts/{}/approve", denied_id.0))
                .header("cookie", &operator)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        repository::get_waf_config(&state.db).await.unwrap().mode,
        WafMode::MonitorOnly
    );

    let stale_id =
        completed_waf_draft(&state, admin_id, DraftWafMode::Block, Some("b".repeat(64))).await;
    let stale = app
        .clone()
        .oneshot(
            Request::post(format!("/api/ai-advisor/drafts/{}/approve", stale_id.0))
                .header("cookie", &admin)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(stale).await["code"], "advisor_stale_draft");

    let expired_id = completed_waf_draft(&state, admin_id, DraftWafMode::Block, None).await;
    sqlx::query("UPDATE ai_advisor_jobs SET expires_at=? WHERE job_id=?")
        .bind((Utc::now() - Duration::minutes(1)).to_rfc3339())
        .bind(&expired_id.0)
        .execute(&state.db)
        .await
        .unwrap();
    let expired = app
        .clone()
        .oneshot(
            Request::post(format!("/api/ai-advisor/drafts/{}/approve", expired_id.0))
                .header("cookie", &admin)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(expired.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(expired).await["code"], "advisor_expired");

    let invalid_id = AdvisorJobId::new();
    let config = repository::get_waf_config(&state.db).await.unwrap();
    let hash = bearust::control_plane::ai_advisor::waf_config_hash(&config);
    let invalid = Redactor::default().redact(&serde_json::json!({
        "workflow": "configuration_draft",
        "summary": "unsafe action",
        "action": "delete_all_rules",
        "mode": "block",
        "expected_config_hash": hash,
    }));
    let invalid_record = repository::insert_advisor_job(
        &state.db,
        &repository::NewAdvisorJob {
            job_id: invalid_id.clone(),
            owner_id: admin_id,
            workflow: AdvisorWorkflow::ConfigurationDraft,
            redacted_input: redacted(r#"{"message":"safe"}"#),
            provider_model: "test-model".into(),
            config_version: config.updated_at,
            config_hash: hash,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
        },
    )
    .await
    .unwrap();
    repository::claim_advisor_job(&state.db, &invalid_record.job_id, Utc::now())
        .await
        .unwrap();
    repository::finish_advisor_job(
        &state.db,
        &invalid_record.job_id,
        AdvisorJobStatus::Completed,
        Some(&invalid),
        None,
        Utc::now(),
    )
    .await
    .unwrap();
    let invalid = app
        .clone()
        .oneshot(
            Request::post(format!("/api/ai-advisor/drafts/{}/approve", invalid_id.0))
                .header("cookie", &admin)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        repository::get_waf_config(&state.db).await.unwrap().mode,
        WafMode::MonitorOnly
    );

    let approved_id = completed_waf_draft(&state, admin_id, DraftWafMode::Block, None).await;
    let mut events = state.realtime.subscribe();
    let approved = app
        .clone()
        .oneshot(
            Request::post(format!("/api/ai-advisor/drafts/{}/approve", approved_id.0))
                .header("cookie", &admin)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(approved.status(), StatusCode::OK);
    assert_eq!(
        repository::get_waf_config(&state.db).await.unwrap().mode,
        WafMode::Block
    );
    assert_eq!(
        repository::get_advisor_job(&state.db, &approved_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        AdvisorJobStatus::Approved
    );
    assert_eq!(events.recv().await.unwrap().kind, "audit");
    assert_eq!(events.recv().await.unwrap().kind, "ai_advisor.changed");

    let duplicate = app
        .clone()
        .oneshot(
            Request::post(format!("/api/ai-advisor/drafts/{}/approve", approved_id.0))
                .header("cookie", &admin)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);

    let rejected_id = completed_waf_draft(&state, admin_id, DraftWafMode::MonitorOnly, None).await;
    let rejected = app
        .oneshot(
            Request::post(format!("/api/ai-advisor/drafts/{}/reject", rejected_id.0))
                .header("cookie", &admin)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::OK);
    assert_eq!(
        repository::get_waf_config(&state.db).await.unwrap().mode,
        WafMode::Block
    );
    assert_eq!(
        repository::get_advisor_job(&state.db, &rejected_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        AdvisorJobStatus::Rejected
    );
}

#[tokio::test]
async fn advisor_waf_approval_transaction_rolls_back_mode_when_decision_write_fails() {
    let provider = r#"{"workflow":"security_summary","summary":"Safe","severity":"info","signals":[],"reason_ids":[],"score":70}"#;
    let (_, state, _, _, _) = api_state(enabled_service(provider)).await;
    let admin_id = repository::find_user(&state.db, "admin@advisor.test")
        .await
        .unwrap()
        .unwrap()
        .0
        .id;
    let job_id = completed_waf_draft(&state, admin_id, DraftWafMode::Block, None).await;
    let before = repository::get_waf_config(&state.db).await.unwrap();
    let expected_hash = bearust::control_plane::ai_advisor::waf_config_hash(&before);
    sqlx::query(
        "CREATE TRIGGER fail_ai_advisor_approval BEFORE UPDATE ON ai_advisor_jobs \
         WHEN NEW.status='approved' BEGIN SELECT RAISE(FAIL, 'forced decision failure'); END",
    )
    .execute(&state.db)
    .await
    .unwrap();

    let result = repository::approve_waf_draft_atomic(
        &state.db,
        &job_id,
        &before.updated_at,
        &expected_hash,
        before.mode,
        WafMode::Block,
        Utc::now(),
    )
    .await;

    assert!(result.is_err());
    assert_eq!(repository::get_waf_config(&state.db).await.unwrap(), before);
    assert_eq!(
        repository::get_advisor_job(&state.db, &job_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        AdvisorJobStatus::Completed
    );
}

#[tokio::test]
async fn advisor_waf_approval_transaction_rejects_hash_mismatch_without_mode_change() {
    let provider = r#"{"workflow":"security_summary","summary":"Safe","severity":"info","signals":[],"reason_ids":[],"score":70}"#;
    let (_, state, _, _, _) = api_state(enabled_service(provider)).await;
    let admin_id = repository::find_user(&state.db, "admin@advisor.test")
        .await
        .unwrap()
        .unwrap()
        .0
        .id;
    let job_id = completed_waf_draft(&state, admin_id, DraftWafMode::Block, None).await;
    let before = repository::get_waf_config(&state.db).await.unwrap();

    let outcome = repository::approve_waf_draft_atomic(
        &state.db,
        &job_id,
        &before.updated_at,
        &"b".repeat(64),
        before.mode,
        WafMode::Block,
        Utc::now(),
    )
    .await
    .unwrap();

    assert_eq!(outcome, repository::WafDraftApprovalOutcome::DraftConflict);
    assert_eq!(repository::get_waf_config(&state.db).await.unwrap(), before);
    assert_eq!(
        repository::get_advisor_job(&state.db, &job_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        AdvisorJobStatus::Completed
    );
}

#[tokio::test]
async fn advisor_reload_failure_compensates_mode_and_draft_without_success_events() {
    let provider = r#"{"workflow":"security_summary","summary":"Safe","severity":"info","signals":[],"reason_ids":[],"score":70}"#;
    let (app, state, admin, _, _) = api_state(enabled_service(provider)).await;
    let admin_id = repository::find_user(&state.db, "admin@advisor.test")
        .await
        .unwrap()
        .unwrap()
        .0
        .id;
    let before = repository::get_waf_config(&state.db).await.unwrap();
    let job_id = completed_waf_draft(&state, admin_id, DraftWafMode::Block, None).await;
    repository::insert_waf_rule(
        &state.db,
        &WafRule {
            id: 0,
            name: "Invalid reload fixture".into(),
            source: "custom".into(),
            category: "test".into(),
            severity: "low".into(),
            enabled: true,
            action: WafAction::Inherit,
            matcher_json: "{".into(),
            created_at: String::new(),
            updated_at: String::new(),
        },
    )
    .await
    .unwrap();
    let mut events = state.realtime.subscribe();

    let response = app
        .oneshot(
            Request::post(format!("/api/ai-advisor/drafts/{}/approve", job_id.0))
                .header("cookie", admin)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(json_body(response).await["code"], "database_error");
    assert_eq!(repository::get_waf_config(&state.db).await.unwrap(), before);
    let draft = repository::get_advisor_job(&state.db, &job_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(draft.status, AdvisorJobStatus::Completed);
    assert!(draft.draft_decision.is_none());
    assert_eq!(state.waf.snapshot().mode, WafMode::MonitorOnly);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), events.recv())
            .await
            .is_err()
    );
    let approvals: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE event='ai_advisor_draft_approved'",
    )
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert_eq!(approvals, 0);
}

#[tokio::test]
async fn advisor_api_bounds_input_and_sanitizes_invalid_provider_output() {
    let raw_provider =
        r#"{"workflow":"security_summary","raw_provider_body":"password=exfiltrate"}"#;
    let (app, state, _, operator, _) = api_state(enabled_service(raw_provider)).await;

    let oversized = app
        .clone()
        .oneshot(
            Request::post("/api/ai-advisor/analyses")
                .header("cookie", &operator)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "workflow": "security_summary",
                        "command": "x".repeat(MAX_ADVISOR_COMMAND_BYTES + 1),
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::BAD_REQUEST);

    let excessive_range = app
        .clone()
        .oneshot(
            Request::post("/api/ai-advisor/analyses")
                .header("cookie", &operator)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"workflow":"security_summary","from":"2026-01-01T00:00:00Z","to":"2026-03-01T00:00:00Z"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(excessive_range.status(), StatusCode::BAD_REQUEST);

    let mut events = state.realtime.subscribe();
    let accepted = app
        .clone()
        .oneshot(
            Request::post("/api/ai-advisor/analyses")
                .header("cookie", &operator)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"workflow":"security_summary"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    let id = AdvisorJobId(json_body(accepted).await["job_id"].as_str().unwrap().into());
    let failed = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let record = repository::get_advisor_job(&state.db, &id)
                .await
                .unwrap()
                .unwrap();
            if record.status == AdvisorJobStatus::Failed {
                break record;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(failed.error_code, Some(AdvisorErrorCode::InvalidResponse));
    assert!(failed.redacted_result.is_none());

    let insights = app
        .oneshot(
            Request::get("/api/ai-advisor/insights")
                .header("cookie", &operator)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let serialized = json_body(insights).await.to_string();
    assert!(serialized.contains("advisor_invalid_response"));
    assert!(!serialized.contains("exfiltrate"));
    assert!(!serialized.contains("raw_provider_body"));

    for expected in ["audit", "ai_advisor.changed", "audit", "ai_advisor.changed"] {
        assert_eq!(events.recv().await.unwrap().kind, expected);
    }
    let audit_details: Vec<String> =
        sqlx::query_scalar("SELECT details FROM audit_logs WHERE event LIKE 'ai_advisor_%'")
            .fetch_all(&state.db)
            .await
            .unwrap();
    assert!(!audit_details.join(";").contains("exfiltrate"));
}

#[tokio::test]
async fn worker_validates_untrusted_schema_and_preserves_supplied_job_id() {
    let valid = r#"{"workflow":"security_summary","summary":"Safe summary","severity":"info","signals":[],"reason_ids":[],"score":70}"#;
    let service = enabled_service(valid);
    let id = AdvisorJobId::new();
    service
        .enqueue_with_id(
            id.clone(),
            AdvisorRequest {
                workflow: AdvisorWorkflow::SecuritySummary,
                host_id: None,
                from: None,
                to: None,
                command: Some("bounded prompt".into()),
            },
        )
        .unwrap();
    assert_eq!(
        terminal_response(&service, &id).await.status,
        AdvisorJobStatus::Completed
    );
    assert_eq!(service.validated_result(&id).unwrap().value()["score"], 70);

    let invalid = enabled_service(r#"{"workflow":"security_summary","raw":"provider body"}"#);
    let invalid_id = AdvisorJobId::new();
    invalid
        .enqueue_with_id(
            invalid_id.clone(),
            AdvisorRequest {
                workflow: AdvisorWorkflow::SecuritySummary,
                host_id: None,
                from: None,
                to: None,
                command: Some("bounded prompt".into()),
            },
        )
        .unwrap();
    let failed = terminal_response(&invalid, &invalid_id).await;
    assert_eq!(failed.status, AdvisorJobStatus::Failed);
    assert_eq!(failed.error_code, Some(AdvisorErrorCode::InvalidResponse));
    assert!(invalid.validated_result(&invalid_id).is_none());
}

fn job(_id: &str, owner_id: i64, workflow: AdvisorWorkflow) -> repository::NewAdvisorJob {
    let now = Utc::now();
    repository::NewAdvisorJob {
        job_id: uuid::Uuid::parse_str(_id)
            .map(|_| AdvisorJobId(_id.into()))
            .unwrap_or_default(),
        owner_id,
        workflow,
        redacted_input: redacted(r#"{"message":"[REDACTED]"}"#),
        provider_model: "gpt-4o-mini".into(),
        config_version: "v1".into(),
        config_hash: "a".repeat(64),
        created_at: now,
        expires_at: now + Duration::hours(1),
    }
}

#[tokio::test]
async fn advisor_migration_is_idempotent_and_seeds_builtin_permissions() {
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&pool).await.unwrap();
    repository::migrate(&pool).await.unwrap();

    let keys: Vec<String> = sqlx::query_scalar(
        "SELECT key FROM permissions WHERE key LIKE 'ai_advisor.%' ORDER BY key",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        keys,
        [
            "ai_advisor.approve",
            "ai_advisor.read",
            "ai_advisor.request"
        ]
    );
    assert_eq!(Permission::AiAdvisorRead.key(), "ai_advisor.read");
    for (slug, expected) in [
        (
            "admin",
            vec![
                "ai_advisor.approve",
                "ai_advisor.read",
                "ai_advisor.request",
                "audit_logs.export",
                "audit_logs.read",
                "bot_protection.manage",
                "certificates.read",
                "certificates.write",
                "plugins.manage",
                "plugins.read",
                "proxy_hosts.read",
                "proxy_hosts.write",
                "roles.manage",
                "sessions.revoke",
                "system.settings.manage",
                "users.manage",
            ],
        ),
        (
            "operator",
            vec![
                "ai_advisor.read",
                "ai_advisor.request",
                "audit_logs.read",
                "certificates.read",
                "certificates.write",
                "proxy_hosts.read",
                "proxy_hosts.write",
            ],
        ),
        (
            "viewer",
            vec![
                "ai_advisor.read",
                "audit_logs.read",
                "certificates.read",
                "proxy_hosts.read",
            ],
        ),
    ] {
        let role = repository::role_by_slug(&pool, slug)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            repository::role_permissions(&pool, role.id).await.unwrap(),
            expected
        );
    }
}

#[test]
fn advisor_permissions_match_role_policy() {
    use bearust::control_plane::rbac::{allowed, Role};
    assert!(allowed(Role::Viewer, Permission::AiAdvisorRead));
    assert!(!allowed(Role::Viewer, Permission::AiAdvisorRequest));
    assert!(allowed(Role::Operator, Permission::AiAdvisorRequest));
    assert!(!allowed(Role::Operator, Permission::AiAdvisorApprove));
    assert!(allowed(Role::Admin, Permission::AiAdvisorApprove));
}

#[tokio::test]
async fn advisor_job_transitions_are_guarded_and_terminal_once() {
    let pool = pool().await;
    let inserted = repository::insert_advisor_job(
        &pool,
        &job("job-transition", 7, AdvisorWorkflow::ConfigurationDraft),
    )
    .await
    .unwrap();
    assert_eq!(inserted.status, AdvisorJobStatus::Queued);
    assert!(
        repository::claim_advisor_job(&pool, &inserted.job_id, Utc::now())
            .await
            .unwrap()
    );
    assert!(repository::finish_advisor_job(
        &pool,
        &inserted.job_id,
        AdvisorJobStatus::Completed,
        Some(&redacted(r#"{"message":"safe"}"#)),
        None,
        Utc::now(),
    )
    .await
    .unwrap());
    assert!(!repository::finish_advisor_job(
        &pool,
        &inserted.job_id,
        AdvisorJobStatus::Failed,
        None,
        Some(AdvisorErrorCode::Timeout),
        Utc::now(),
    )
    .await
    .unwrap());
    assert!(
        repository::mark_advisor_draft_decision(&pool, &inserted.job_id, true, Utc::now())
            .await
            .unwrap()
    );
    assert!(
        !repository::mark_advisor_draft_decision(&pool, &inserted.job_id, false, Utc::now())
            .await
            .unwrap()
    );
    assert_eq!(
        repository::get_advisor_job(&pool, &inserted.job_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        AdvisorJobStatus::Approved
    );
    let decided = repository::get_advisor_job(&pool, &inserted.job_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        decided.draft_decision,
        Some(bearust::control_plane::models::AdvisorDraftDecision::Approved)
    );
    assert!(decided.draft_decided_at.is_some());
}

#[tokio::test]
async fn advisor_repository_expires_queued_jobs() {
    let pool = pool().await;
    let mut expired = job("job-expired", 7, AdvisorWorkflow::IncidentExplanation);
    expired.expires_at = Utc::now() - Duration::seconds(1);
    repository::insert_advisor_job(&pool, &expired)
        .await
        .unwrap();
    assert!(
        !repository::claim_advisor_job(&pool, &expired.job_id, Utc::now())
            .await
            .unwrap()
    );
    assert_eq!(
        repository::get_advisor_job(&pool, &expired.job_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        AdvisorJobStatus::Expired
    );
}

#[tokio::test]
async fn advisor_repository_only_persists_validated_redacted_json_and_metadata() {
    let pool = pool().await;
    let mut raw = job("job-raw", 7, AdvisorWorkflow::IncidentExplanation);
    let custom = Redactor::with_secret_keys(["tenant_secret"])
        .redact(&serde_json::json!({"message":"tenant_secret=tenant-value"}));
    assert!(!custom.value().to_string().contains("tenant-value"));
    raw.redacted_input = custom;
    assert!(repository::insert_advisor_job(&pool, &raw).await.is_ok());
    let valid = job(
        &AdvisorJobId::new().0,
        7,
        AdvisorWorkflow::IncidentExplanation,
    );
    assert!(repository::insert_advisor_job(&pool, &valid).await.is_ok());

    let mut invalid_id = valid.clone();
    invalid_id.job_id = AdvisorJobId("not-a-uuid".into());
    assert!(repository::insert_advisor_job(&pool, &invalid_id)
        .await
        .is_err());

    for model in ["", &"m".repeat(129)] {
        let mut invalid = valid.clone();
        invalid.job_id = AdvisorJobId::new();
        invalid.provider_model = model.to_owned();
        assert!(repository::insert_advisor_job(&pool, &invalid)
            .await
            .is_err());
    }
    for version in ["", &"v".repeat(65)] {
        let mut invalid = valid.clone();
        invalid.job_id = AdvisorJobId::new();
        invalid.config_version = version.to_owned();
        assert!(repository::insert_advisor_job(&pool, &invalid)
            .await
            .is_err());
    }
    for hash in ["", &"a".repeat(63), &"a".repeat(65), &"z".repeat(64)] {
        let mut invalid = valid.clone();
        invalid.job_id = AdvisorJobId::new();
        invalid.config_hash = hash.to_owned();
        assert!(repository::insert_advisor_job(&pool, &invalid)
            .await
            .is_err());
    }

    let mut exact_bounds = valid;
    exact_bounds.job_id = AdvisorJobId::new();
    exact_bounds.provider_model = "m".repeat(128);
    exact_bounds.config_version = "v".repeat(64);
    exact_bounds.config_hash = "f".repeat(64);
    assert!(repository::insert_advisor_job(&pool, &exact_bounds)
        .await
        .is_ok());
}

#[tokio::test]
async fn advisor_error_codes_and_terminal_statuses_round_trip_without_overwrite() {
    let pool = pool().await;
    for (index, error) in [
        AdvisorErrorCode::Disabled,
        AdvisorErrorCode::Busy,
        AdvisorErrorCode::Timeout,
        AdvisorErrorCode::ProviderUnavailable,
        AdvisorErrorCode::InvalidResponse,
        AdvisorErrorCode::ResponseTooLarge,
        AdvisorErrorCode::CircuitOpen,
        AdvisorErrorCode::InvalidRequest,
        AdvisorErrorCode::StaleDraft,
        AdvisorErrorCode::Expired,
    ]
    .into_iter()
    .enumerate()
    {
        let id = AdvisorJobId::new();
        let record = repository::insert_advisor_job(
            &pool,
            &job(
                &id.0,
                index as i64 + 1,
                AdvisorWorkflow::IncidentExplanation,
            ),
        )
        .await
        .unwrap();
        assert!(
            repository::claim_advisor_job(&pool, &record.job_id, Utc::now())
                .await
                .unwrap()
        );
        assert!(repository::finish_advisor_job(
            &pool,
            &record.job_id,
            AdvisorJobStatus::Failed,
            None,
            Some(error),
            Utc::now()
        )
        .await
        .unwrap());
        assert_eq!(
            repository::get_advisor_job(&pool, &record.job_id)
                .await
                .unwrap()
                .unwrap()
                .error_code,
            Some(error)
        );
    }
}

#[tokio::test]
async fn advisor_rejected_and_running_expired_transitions_are_guarded() {
    let pool = pool().await;
    let draft = repository::insert_advisor_job(
        &pool,
        &job(
            &AdvisorJobId::new().0,
            9,
            AdvisorWorkflow::ConfigurationDraft,
        ),
    )
    .await
    .unwrap();
    assert!(
        repository::claim_advisor_job(&pool, &draft.job_id, Utc::now())
            .await
            .unwrap()
    );
    assert!(repository::finish_advisor_job(
        &pool,
        &draft.job_id,
        AdvisorJobStatus::Completed,
        Some(&redacted(r#"{"message":"draft"}"#)),
        None,
        Utc::now()
    )
    .await
    .unwrap());
    assert!(
        repository::mark_advisor_draft_decision(&pool, &draft.job_id, false, Utc::now())
            .await
            .unwrap()
    );
    assert_eq!(
        repository::get_advisor_job(&pool, &draft.job_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        AdvisorJobStatus::Rejected
    );
    let expired = job(
        &AdvisorJobId::new().0,
        9,
        AdvisorWorkflow::IncidentExplanation,
    );
    let expired = repository::insert_advisor_job(&pool, &expired)
        .await
        .unwrap();
    assert!(
        repository::claim_advisor_job(&pool, &expired.job_id, Utc::now())
            .await
            .unwrap()
    );
    assert!(repository::finish_advisor_job(
        &pool,
        &expired.job_id,
        AdvisorJobStatus::Expired,
        None,
        Some(AdvisorErrorCode::Expired),
        Utc::now(),
    )
    .await
    .unwrap());
    let expired = repository::get_advisor_job(&pool, &expired.job_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(expired.status, AdvisorJobStatus::Expired);
    assert_eq!(expired.error_code, Some(AdvisorErrorCode::Expired));
    assert_eq!(expired.redacted_result, None);
}

#[tokio::test]
async fn advisor_jobs_paginate_by_owner_newest_first() {
    let pool = pool().await;
    let ascending_ids = [
        AdvisorJobId("00000000-0000-4000-8000-000000000001".into()),
        AdvisorJobId("00000000-0000-4000-8000-000000000002".into()),
        AdvisorJobId("00000000-0000-4000-8000-000000000003".into()),
    ];
    let tied_created_at = Utc::now();
    for id in &ascending_ids {
        let mut record = job(&id.0, 7, AdvisorWorkflow::SecuritySummary);
        record.job_id = id.clone();
        record.created_at = tied_created_at;
        repository::insert_advisor_job(&pool, &record)
            .await
            .unwrap();
    }
    repository::insert_advisor_job(
        &pool,
        &job("other-owner", 8, AdvisorWorkflow::SecuritySummary),
    )
    .await
    .unwrap();
    let page = repository::list_advisor_jobs(&pool, 7, 2, 1).await.unwrap();
    assert_eq!(page.total, 3);
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.items[0].job_id, ascending_ids[2]);
    assert_eq!(page.items[1].job_id, ascending_ids[1]);
    let page2 = repository::list_advisor_jobs(&pool, 7, 2, 2).await.unwrap();
    assert_eq!(page2.items[0].job_id, ascending_ids[0]);
}

#[tokio::test]
async fn external_advisor_migration_skips_without_opt_in_database() {
    let Some(url) = support::external_database_url() else {
        return;
    };
    let target = support::redacted_database_target(&url);
    let pool = repository::connect(&url)
        .await
        .unwrap_or_else(|_| panic!("connect external {target}"));
    repository::migrate(&pool)
        .await
        .unwrap_or_else(|_| panic!("migrate external {target}"));
    repository::migrate(&pool)
        .await
        .unwrap_or_else(|_| panic!("repeat external migration {target}"));
    let owner_id = (uuid::Uuid::new_v4().as_u128() % (i64::MAX as u128 - 1)) as i64 + 1;
    let first_id = AdvisorJobId::new();
    let lifecycle = AssertUnwindSafe(async {
        let inserted = repository::insert_advisor_job(
            &pool,
            &job(&first_id.0, owner_id, AdvisorWorkflow::IncidentExplanation),
        )
        .await
        .unwrap();
        assert!(
            repository::claim_advisor_job(&pool, &inserted.job_id, Utc::now())
                .await
                .unwrap()
        );
        assert!(repository::finish_advisor_job(
            &pool,
            &inserted.job_id,
            AdvisorJobStatus::Completed,
            Some(&redacted(r#"{"message":"ok"}"#)),
            None,
            Utc::now()
        )
        .await
        .unwrap());
        assert!(repository::get_advisor_job(&pool, &inserted.job_id)
            .await
            .unwrap()
            .is_some());
        assert_eq!(
            repository::list_advisor_jobs(&pool, owner_id, 10, 1)
                .await
                .unwrap()
                .total,
            1
        );

        let draft_id = AdvisorJobId::new();
        let draft = repository::insert_advisor_job(
            &pool,
            &job(&draft_id.0, owner_id, AdvisorWorkflow::ConfigurationDraft),
        )
        .await
        .unwrap();
        assert!(
            repository::claim_advisor_job(&pool, &draft.job_id, Utc::now())
                .await
                .unwrap()
        );
        assert!(repository::finish_advisor_job(
            &pool,
            &draft.job_id,
            AdvisorJobStatus::Completed,
            Some(&redacted(r#"{"message":"draft"}"#)),
            None,
            Utc::now()
        )
        .await
        .unwrap());
        assert!(
            repository::mark_advisor_draft_decision(&pool, &draft.job_id, true, Utc::now())
                .await
                .unwrap()
        );
        assert_eq!(
            repository::list_advisor_jobs(&pool, owner_id, 10, 1)
                .await
                .unwrap()
                .total,
            2
        );
    })
    .catch_unwind()
    .await;

    let cleanup = sqlx::query("DELETE FROM ai_advisor_jobs WHERE owner_id=?")
        .bind(owner_id)
        .execute(&pool)
        .await;
    let remaining = repository::list_advisor_jobs(&pool, owner_id, 10, 1).await;
    pool.close().await;

    if let Err(panic) = lifecycle {
        if let Err(error) = cleanup {
            eprintln!("external advisor cleanup also failed: {error}");
        }
        std::panic::resume_unwind(panic);
    }
    cleanup.unwrap();
    assert_eq!(remaining.unwrap().total, 0);
}
