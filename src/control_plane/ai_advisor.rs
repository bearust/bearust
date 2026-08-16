use super::{audit, authorize, current, repository, user_error, AppState};
use crate::ai_advisor::{
    build_workflow_prompt, validate_workflow_output, AdvisorErrorCode, AdvisorJobId,
    AdvisorJobStatus, AdvisorRequest, AdvisorStatus, AdvisorWorkflow, ConfigurationDraft,
    DraftAction, DraftWafMode, RedactedValue, Redactor, MAX_ADVISOR_COMMAND_BYTES,
};
use crate::control_plane::models::{AdvisorJobPage, AdvisorJobRecord, WafMode};
use crate::control_plane::rbac::{Permission, ResourceContext};
use axum::{
    extract::{rejection::JsonRejection, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_ANALYSIS_RANGE_DAYS: i64 = 31;
const ADVISOR_JOB_TTL_HOURS: i64 = 1;
const PERIODIC_REPORT_TTL_HOURS: i64 = 24 * 31;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisInput {
    pub workflow: AdvisorWorkflow,
    pub host_id: Option<i64>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub command: Option<String>,
}

impl AnalysisInput {
    fn validate(&self) -> Result<(), AdvisorErrorCode> {
        if self.host_id.is_some_and(|id| id <= 0)
            || self
                .command
                .as_deref()
                .is_some_and(|value| value.len() > MAX_ADVISOR_COMMAND_BYTES)
            || self.from.zip(self.to).is_some_and(|(from, to)| {
                from > to
                    || to.signed_duration_since(from) > Duration::days(MAX_ANALYSIS_RANGE_DAYS)
            })
        {
            return Err(AdvisorErrorCode::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InsightQuery {
    page: Option<u32>,
    page_size: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
struct AdvisorJobView {
    job_id: AdvisorJobId,
    workflow: AdvisorWorkflow,
    status: AdvisorJobStatus,
    redacted_input: serde_json::Value,
    redacted_result: Option<serde_json::Value>,
    error_code: Option<AdvisorErrorCode>,
    provider_model: String,
    config_version: String,
    config_hash: String,
    created_at: String,
    updated_at: String,
    expires_at: String,
    draft_decision: Option<crate::control_plane::models::AdvisorDraftDecision>,
    draft_decided_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize)]
struct AdvisorJobPageView {
    items: Vec<AdvisorJobView>,
    page: u32,
    page_size: u32,
    total: i64,
}

fn job_view(record: AdvisorJobRecord) -> Result<AdvisorJobView, ()> {
    Ok(AdvisorJobView {
        job_id: record.job_id,
        workflow: record.workflow,
        status: record.status,
        redacted_input: serde_json::from_str(&record.redacted_input).map_err(|_| ())?,
        redacted_result: record
            .redacted_result
            .map(|value| serde_json::from_str(&value).map_err(|_| ()))
            .transpose()?,
        error_code: record.error_code,
        provider_model: record.provider_model,
        config_version: record.config_version,
        config_hash: record.config_hash,
        created_at: record.created_at,
        updated_at: record.updated_at,
        expires_at: record.expires_at,
        draft_decision: record.draft_decision,
        draft_decided_at: record.draft_decided_at,
    })
}

fn page_view(page: AdvisorJobPage) -> Result<AdvisorJobPageView, ()> {
    Ok(AdvisorJobPageView {
        items: page
            .items
            .into_iter()
            .map(job_view)
            .collect::<Result<_, _>>()?,
        page: page.page,
        page_size: page.page_size,
        total: page.total,
    })
}

async fn require_permission(
    state: &AppState,
    headers: &HeaderMap,
    permission: Permission,
) -> Result<crate::control_plane::models::User, Response> {
    let user = current(state, headers).await.map_err(|_| {
        user_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Authentication required",
        )
    })?;
    if !authorize(&state.db, &user, permission, ResourceContext::GLOBAL)
        .await
        .unwrap_or(false)
    {
        audit::record_state(
            state,
            Some(user.id),
            "ai_advisor_authorization_denied",
            &format!("permission={}", permission.key()),
        )
        .await;
        return Err(user_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Permission denied",
        ));
    }
    Ok(user)
}

fn advisor_error(error: AdvisorErrorCode) -> Response {
    match error {
        AdvisorErrorCode::Disabled => user_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "advisor_disabled",
            "AI advisor is disabled",
        ),
        AdvisorErrorCode::Busy => {
            user_error(StatusCode::CONFLICT, "advisor_busy", "AI advisor is busy")
        }
        AdvisorErrorCode::InvalidRequest => user_error(
            StatusCode::BAD_REQUEST,
            "advisor_invalid_request",
            "Invalid advisor request",
        ),
        AdvisorErrorCode::StaleDraft => user_error(
            StatusCode::CONFLICT,
            "advisor_stale_draft",
            "Advisor draft is stale",
        ),
        AdvisorErrorCode::Expired => user_error(
            StatusCode::CONFLICT,
            "advisor_expired",
            "Advisor draft has expired",
        ),
        _ => user_error(
            StatusCode::BAD_GATEWAY,
            "advisor_unavailable",
            "AI advisor is unavailable",
        ),
    }
}

pub(super) async fn status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_permission(&state, &headers, Permission::AiAdvisorRead).await {
        return response;
    }
    Json(state.ai_advisor.status()).into_response()
}

pub(super) async fn create_analysis(
    State(state): State<AppState>,
    headers: HeaderMap,
    input: Result<Json<AnalysisInput>, JsonRejection>,
) -> Response {
    let user = match require_permission(&state, &headers, Permission::AiAdvisorRequest).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if state.ai_advisor.status() != (AdvisorStatus { enabled: true }) {
        return advisor_error(AdvisorErrorCode::Disabled);
    }
    let Json(input) = match input {
        Ok(input) => input,
        Err(_) => return advisor_error(AdvisorErrorCode::InvalidRequest),
    };
    if let Err(error) = input.validate() {
        return advisor_error(error);
    }
    let (snapshot, config_version, config_hash) = match advisor_snapshot(&state, &input).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let locale = user.preferred_locale.as_deref().unwrap_or("en");
    let prompt = match build_workflow_prompt(input.workflow.clone(), &snapshot, locale) {
        Ok(prompt) => prompt,
        Err(error) => return advisor_error(error),
    };
    let model = state
        .ai_advisor
        .config()
        .map(|config| config.model.to_string())
        .unwrap_or_else(|| "unavailable".into());
    let job_id = AdvisorJobId::new();
    let now = Utc::now();
    let record = match repository::insert_advisor_job(
        &state.db,
        &repository::NewAdvisorJob {
            job_id: job_id.clone(),
            owner_id: user.id,
            workflow: input.workflow.clone(),
            redacted_input: snapshot,
            provider_model: model,
            config_version,
            config_hash,
            created_at: now,
            expires_at: now + Duration::hours(ADVISOR_JOB_TTL_HOURS),
        },
    )
    .await
    {
        Ok(record) => record,
        Err(_) => {
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database unavailable",
            )
        }
    };
    let request = AdvisorRequest {
        workflow: input.workflow,
        host_id: input.host_id,
        from: input.from,
        to: input.to,
        command: Some(prompt),
    };
    if let Err(error) = state.ai_advisor.enqueue_with_id(job_id.clone(), request) {
        let _ = repository::claim_advisor_job(&state.db, &job_id, Utc::now()).await;
        let _ = repository::finish_advisor_job(
            &state.db,
            &job_id,
            AdvisorJobStatus::Failed,
            None,
            Some(error),
            Utc::now(),
        )
        .await;
        return advisor_error(error);
    }
    audit::record_state(
        &state,
        Some(user.id),
        "ai_advisor_requested",
        &format!("job_id={};workflow={:?}", job_id.0, record.workflow),
    )
    .await;
    state.realtime.publish("ai_advisor.changed");
    tokio::spawn(synchronize_job(state.clone(), user.id, job_id));
    (StatusCode::ACCEPTED, Json(job_view(record).unwrap())).into_response()
}

/// Queue the periodic security summary described by the PRD. The report is
/// persisted as a normal advisor job, so it is visible in the same insights
/// view and follows the same redaction, timeout, and circuit-breaker rules as
/// an operator-requested analysis.
pub(crate) async fn schedule_security_summary(
    state: &AppState,
) -> Result<Option<AdvisorJobId>, AdvisorErrorCode> {
    if state.ai_advisor.status() != (AdvisorStatus { enabled: true }) {
        return Ok(None);
    }
    // A configured cluster has one scheduler owner. This prevents every node
    // from enqueueing the same 24-hour report into a shared control database;
    // a node without an elected leader simply waits for the next interval.
    let cluster = state.cluster.snapshot().await;
    if cluster.cluster_enabled
        && cluster.raft_leader_id.as_deref() != Some(cluster.local_node_id.as_str())
    {
        return Ok(None);
    }
    let owner = repository::list_users(&state.db)
        .await
        .map_err(|_| AdvisorErrorCode::ProviderUnavailable)?
        .into_iter()
        .find(|user| user.role == "admin" && !user.disabled);
    let Some(owner) = owner else {
        return Ok(None);
    };
    let now = Utc::now();
    let input = AnalysisInput {
        workflow: AdvisorWorkflow::SecuritySummary,
        host_id: None,
        from: Some(now - Duration::hours(24)),
        to: Some(now),
        command: None,
    };
    let (snapshot, config_version, config_hash) = advisor_snapshot(state, &input)
        .await
        .map_err(|_| AdvisorErrorCode::ProviderUnavailable)?;
    let locale = owner.preferred_locale.as_deref().unwrap_or("en");
    let prompt = build_workflow_prompt(input.workflow.clone(), &snapshot, locale)?;
    let model = state
        .ai_advisor
        .config()
        .map(|config| config.model.to_string())
        .unwrap_or_else(|| "unavailable".into());
    let job_id = AdvisorJobId::new();
    let _record = repository::insert_advisor_job(
        &state.db,
        &repository::NewAdvisorJob {
            job_id: job_id.clone(),
            owner_id: owner.id,
            workflow: input.workflow.clone(),
            redacted_input: snapshot,
            provider_model: model,
            config_version,
            config_hash,
            created_at: now,
            expires_at: now + Duration::hours(PERIODIC_REPORT_TTL_HOURS),
        },
    )
    .await
    .map_err(|_| AdvisorErrorCode::ProviderUnavailable)?;
    let request = AdvisorRequest {
        workflow: input.workflow,
        host_id: input.host_id,
        from: input.from,
        to: input.to,
        command: Some(prompt),
    };
    if let Err(error) = state.ai_advisor.enqueue_with_id(job_id.clone(), request) {
        let _ = repository::claim_advisor_job(&state.db, &job_id, Utc::now()).await;
        let _ = repository::finish_advisor_job(
            &state.db,
            &job_id,
            AdvisorJobStatus::Failed,
            None,
            Some(error),
            Utc::now(),
        )
        .await;
        return Err(error);
    }
    audit::record_state(
        state,
        Some(owner.id),
        "ai_advisor_periodic_report_requested",
        &format!("job_id={};workflow=security_summary", job_id.0),
    )
    .await;
    state.realtime.publish("ai_advisor.changed");
    tokio::spawn(synchronize_job(state.clone(), owner.id, job_id.clone()));
    Ok(Some(job_id))
}

pub(super) async fn list_insights(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<InsightQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let user = match require_permission(&state, &headers, Permission::AiAdvisorRead).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Query(query) = match query {
        Ok(query) => query,
        Err(_) => return advisor_error(AdvisorErrorCode::InvalidRequest),
    };
    match repository::list_advisor_jobs(
        &state.db,
        user.id,
        query.page_size.unwrap_or(20),
        query.page.unwrap_or(1),
    )
    .await
    .map_err(|_| ())
    .and_then(page_view)
    {
        Ok(page) => Json(page).into_response(),
        Err(_) => user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Database unavailable",
        ),
    }
}

pub(super) async fn approve_draft(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let actor = match require_permission(&state, &headers, Permission::AiAdvisorApprove).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let job_id = match advisor_job_id(id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let _guard = state.ai_advisor.lock_approval().await;
    let record = match draft_record(&state, &job_id).await {
        Ok(record) => record,
        Err(response) => return response,
    };
    if let Err(response) = active_completed_draft(&record) {
        return response;
    }
    let Some(raw_result) = record.redacted_result.as_deref() else {
        return advisor_error(AdvisorErrorCode::InvalidRequest);
    };
    let validated = match validate_workflow_output(AdvisorWorkflow::ConfigurationDraft, raw_result)
    {
        Ok(value) => value,
        Err(_) => return advisor_error(AdvisorErrorCode::InvalidRequest),
    };
    let draft: ConfigurationDraft = match serde_json::from_value(validated.value().clone()) {
        Ok(draft) => draft,
        Err(_) => return advisor_error(AdvisorErrorCode::InvalidRequest),
    };
    if draft.action != DraftAction::SetWafMode {
        return advisor_error(AdvisorErrorCode::InvalidRequest);
    }
    let current = match repository::get_waf_config(&state.db).await {
        Ok(config) => config,
        Err(_) => return database_error(),
    };
    let current_hash = waf_config_hash(&current);
    if record.config_version != current.updated_at
        || record.config_hash != current_hash
        || draft.expected_config_hash != current_hash
    {
        return advisor_error(AdvisorErrorCode::StaleDraft);
    }
    let next_mode = match draft.mode {
        DraftWafMode::MonitorOnly => WafMode::MonitorOnly,
        DraftWafMode::Block => WafMode::Block,
    };
    let applied_at = match repository::approve_waf_draft_atomic(
        &state.db,
        &job_id,
        &record.config_version,
        &record.config_hash,
        current.mode,
        next_mode,
        Utc::now(),
    )
    .await
    {
        Ok(repository::WafDraftApprovalOutcome::Applied { applied_at }) => applied_at,
        Ok(repository::WafDraftApprovalOutcome::StaleConfig) => {
            return advisor_error(AdvisorErrorCode::StaleDraft)
        }
        Ok(repository::WafDraftApprovalOutcome::DraftConflict) => return draft_conflict(),
        Err(_) => return database_error(),
    };
    if state.waf.reload(&state.db).await.is_err() {
        let compensated = repository::compensate_waf_draft_approval(
            &state.db,
            &job_id,
            next_mode,
            &applied_at,
            &current,
            Utc::now(),
        )
        .await
        .unwrap_or(false);
        if compensated {
            let _ = state.waf.reload(&state.db).await;
        }
        return database_error();
    }
    audit::record_state(
        &state,
        Some(actor.id),
        "ai_advisor_draft_approved",
        &format!(
            "job_id={};action=set_waf_mode;mode={:?}",
            job_id.0, next_mode
        ),
    )
    .await;
    state.realtime.publish("ai_advisor.changed");
    state.advisor_metrics.record_job("approved");
    match repository::get_advisor_job(&state.db, &job_id)
        .await
        .ok()
        .flatten()
        .and_then(|record| job_view(record).ok())
    {
        Some(record) => Json(record).into_response(),
        None => database_error(),
    }
}

pub(super) async fn reject_draft(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let actor = match require_permission(&state, &headers, Permission::AiAdvisorApprove).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let job_id = match advisor_job_id(id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let _guard = state.ai_advisor.lock_approval().await;
    let record = match draft_record(&state, &job_id).await {
        Ok(record) => record,
        Err(response) => return response,
    };
    if let Err(response) = active_completed_draft(&record) {
        return response;
    }
    if !repository::mark_advisor_draft_decision(&state.db, &job_id, false, Utc::now())
        .await
        .unwrap_or(false)
    {
        return draft_conflict();
    }
    audit::record_state(
        &state,
        Some(actor.id),
        "ai_advisor_draft_rejected",
        &format!("job_id={};action=reject", job_id.0),
    )
    .await;
    state.realtime.publish("ai_advisor.changed");
    state.advisor_metrics.record_job("rejected");
    match repository::get_advisor_job(&state.db, &job_id)
        .await
        .ok()
        .flatten()
        .and_then(|record| job_view(record).ok())
    {
        Some(record) => Json(record).into_response(),
        None => database_error(),
    }
}

fn advisor_job_id(value: String) -> Result<AdvisorJobId, Response> {
    uuid::Uuid::parse_str(&value)
        .map(|_| AdvisorJobId(value))
        .map_err(|_| advisor_error(AdvisorErrorCode::InvalidRequest))
}

async fn draft_record(
    state: &AppState,
    job_id: &AdvisorJobId,
) -> Result<AdvisorJobRecord, Response> {
    match repository::get_advisor_job(&state.db, job_id).await {
        Ok(Some(record)) if record.workflow == AdvisorWorkflow::ConfigurationDraft => Ok(record),
        Ok(Some(_)) | Ok(None) => Err(user_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "Advisor draft not found",
        )),
        Err(_) => Err(database_error()),
    }
}

fn active_completed_draft(record: &AdvisorJobRecord) -> Result<(), Response> {
    if record.status != AdvisorJobStatus::Completed {
        return Err(draft_conflict());
    }
    let expires_at = DateTime::parse_from_rfc3339(&record.expires_at)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| advisor_error(AdvisorErrorCode::InvalidRequest))?;
    if expires_at <= Utc::now() {
        return Err(advisor_error(AdvisorErrorCode::Expired));
    }
    Ok(())
}

fn draft_conflict() -> Response {
    user_error(
        StatusCode::CONFLICT,
        "advisor_conflict",
        "Advisor draft is no longer pending",
    )
}

fn database_error() -> Response {
    user_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "database_error",
        "Database unavailable",
    )
}

async fn advisor_snapshot(
    state: &AppState,
    input: &AnalysisInput,
) -> Result<(RedactedValue, String, String), Response> {
    let waf = repository::get_waf_config(&state.db).await.map_err(|_| {
        user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Database unavailable",
        )
    })?;
    let rules = repository::list_waf_rules(&state.db).await.map_err(|_| {
        user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Database unavailable",
        )
    })?;
    let analytics = state.analytics.snapshot();
    let anomalies = state
        .anomaly
        .get_anomalies(input.host_id, None, None)
        .into_iter()
        .rev()
        .take(10)
        .map(|record| {
            serde_json::json!({
                "reason_id": record.id.to_string(),
                "host_id": record.host_id,
                "category": record.rule,
                "severity": record.severity,
                "score": record.score,
                "summary": record.summary,
                "timestamp": record.observed_at,
            })
        })
        .collect::<Vec<_>>();
    let config_hash = waf_config_hash(&waf);
    let snapshot = serde_json::json!({
        "workflow": input.workflow,
        "host_id": input.host_id,
        "from": input.from,
        "to": input.to,
        "command": input.command,
        "summary": format!(
            "requests={};status_4xx={};status_5xx={};waf_blocks={};rate_limited={}",
            analytics.summary.requests,
            analytics.summary.status_4xx,
            analytics.summary.status_5xx,
            analytics.summary.waf_blocks,
            analytics.summary.rate_limited,
        ),
        "events": anomalies,
        "details": {
            "mode": waf.mode,
            "count": rules.len(),
            "reason_id": config_hash,
        },
    });
    Ok((
        Redactor::default().redact(&snapshot),
        waf.updated_at,
        config_hash,
    ))
}

pub fn waf_config_hash(config: &crate::control_plane::models::WafConfig) -> String {
    let encoded = serde_json::to_vec(config).unwrap_or_default();
    hex::encode(Sha256::digest(&encoded))
}

async fn synchronize_job(state: AppState, owner_id: i64, job_id: AdvisorJobId) {
    let mut claimed = false;
    loop {
        let Some(response) = state.ai_advisor.result(&job_id) else {
            return;
        };
        match response.status {
            AdvisorJobStatus::Queued => {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            AdvisorJobStatus::Running => {
                if !claimed {
                    claimed = repository::claim_advisor_job(&state.db, &job_id, Utc::now())
                        .await
                        .unwrap_or(false);
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            AdvisorJobStatus::Completed | AdvisorJobStatus::Failed => {
                if !claimed {
                    claimed = repository::claim_advisor_job(&state.db, &job_id, Utc::now())
                        .await
                        .unwrap_or(false);
                }
                if !claimed {
                    return;
                }
                let result = state.ai_advisor.validated_result(&job_id);
                if repository::finish_advisor_job(
                    &state.db,
                    &job_id,
                    response.status,
                    result.as_ref(),
                    response.error_code,
                    Utc::now(),
                )
                .await
                .unwrap_or(false)
                {
                    let outcome = if response.status == AdvisorJobStatus::Completed {
                        "completed"
                    } else {
                        "failed"
                    };
                    audit::record_state(
                        &state,
                        Some(owner_id),
                        "ai_advisor_finished",
                        &format!("job_id={};outcome={outcome}", job_id.0),
                    )
                    .await;
                    state.realtime.publish("ai_advisor.changed");
                }
                return;
            }
            _ => return,
        }
    }
}
