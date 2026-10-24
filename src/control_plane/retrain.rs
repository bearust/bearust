//! HTTP surface and apply logic for feedback-driven WAF retraining
//! (see [`crate::waf_retrain`]).

use super::{
    audit, publish_committed_command, repository, require_role_admin, submit_policy_state_as,
    user_error, AppState,
};
use crate::cluster_command::CommandActor;
use crate::control_plane::models::WafAction;
use crate::waf_retrain::{recommend, Recommendation, RetrainConfig, RetrainMode};
use axum::{
    extract::{rejection::JsonRejection, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};

fn database_error() -> Response {
    user_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "database_error",
        "Database unavailable",
    )
}

/// Current recommendations, excluding rules already demoted.
async fn pending(state: &AppState) -> Result<(RetrainConfig, Vec<Recommendation>), sqlx::Error> {
    let config = repository::get_retrain_config(&state.db).await?;
    let now = chrono::Utc::now();
    let since = (now - chrono::Duration::days(i64::from(config.window_days))).to_rfc3339();
    let feedback = repository::list_waf_feedback_since(&state.db, &since).await?;
    let tuned: Vec<i64> = repository::list_rule_tunings(&state.db)
        .await?
        .into_iter()
        .map(|t| t.rule_id)
        .collect();
    let recs = recommend(&feedback, &config, now, &tuned);
    Ok((config, recs))
}

/// Apply recommendations: demote Bearust rules to log-only and exclude
/// SecLang/CRS rules by id, then reload and replicate. Returns what was
/// applied. `source` is `auto` (scheduled) or `manual` (operator run).
pub async fn apply(
    state: &AppState,
    actor: CommandActor,
    actor_id: Option<i64>,
    source: &str,
) -> Result<Vec<Recommendation>, Response> {
    let (_, recs) = pending(state).await.map_err(|_| database_error())?;
    if recs.is_empty() {
        return Ok(recs);
    }
    let waf_rules = repository::list_waf_rules(&state.db)
        .await
        .map_err(|_| database_error())?;
    let mut seclang = repository::get_seclang_config(&state.db)
        .await
        .map_err(|_| database_error())?;
    let now = chrono::Utc::now().to_rfc3339();
    for rec in &recs {
        let existing = waf_rules.iter().find(|rule| rule.id == rec.rule_id);
        let (kind, previous_action) = match existing {
            Some(rule) => {
                repository::set_waf_rule_action(&state.db, rule.id, WafAction::Log)
                    .await
                    .map_err(|_| database_error())?;
                (
                    "waf_rule",
                    Some(format!("{:?}", rule.action).to_ascii_lowercase()),
                )
            }
            None => {
                if !seclang.disabled_rule_ids.contains(&rec.rule_id) {
                    seclang.disabled_rule_ids.push(rec.rule_id);
                }
                ("seclang", None)
            }
        };
        repository::insert_rule_tuning(
            &state.db,
            &repository::RuleTuning {
                rule_id: rec.rule_id,
                kind: kind.into(),
                previous_action,
                false_positives: i64::from(rec.false_positives),
                true_positives: i64::from(rec.true_positives),
                source: source.into(),
                created_at: now.clone(),
            },
        )
        .await
        .map_err(|_| database_error())?;
    }
    repository::update_seclang_config(&state.db, &seclang)
        .await
        .map_err(|_| database_error())?;
    state
        .waf
        .reload(&state.db)
        .await
        .map_err(|_| database_error())?;
    let (command, receipt) = submit_policy_state_as(state, actor).await?;
    publish_committed_command(state, &command, &receipt);
    audit::record_state(
        state,
        actor_id,
        "waf_retrain_applied",
        &serde_json::json!({
            "source": source,
            "rule_ids": recs.iter().map(|r| r.rule_id).collect::<Vec<_>>(),
        })
        .to_string(),
    )
    .await;
    state.realtime.publish("waf.changed");
    Ok(recs)
}

/// Scheduled run: applies only in enforce mode, as the system actor.
pub async fn scheduled(state: &AppState) {
    let enforce = repository::get_retrain_config(&state.db)
        .await
        .is_ok_and(|config| config.mode == RetrainMode::Enforce);
    if !enforce {
        return;
    }
    if let Ok(applied) = apply(state, CommandActor::system(), None, "auto").await {
        if !applied.is_empty() {
            tracing::info!(event = "waf_retrain_applied", rules = applied.len());
        }
    }
}

pub async fn get_config(State(s): State<AppState>, h: HeaderMap) -> Response {
    if let Err(response) = require_role_admin(&s, &h).await {
        return response;
    }
    match repository::get_retrain_config(&s.db).await {
        Ok(config) => Json(config).into_response(),
        Err(_) => database_error(),
    }
}

pub async fn update_config(
    State(s): State<AppState>,
    h: HeaderMap,
    input: Result<Json<RetrainConfig>, JsonRejection>,
) -> Response {
    let actor = match require_role_admin(&s, &h).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(Json(config)) = input else {
        return user_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Invalid retraining settings",
        );
    };
    if config.validate().is_err() {
        return user_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Invalid retraining settings",
        );
    }
    if repository::update_retrain_config(&s.db, &config)
        .await
        .is_err()
    {
        return database_error();
    }
    let (command, receipt) = match submit_policy_state_as(&s, super::command_actor(&actor)).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    publish_committed_command(&s, &command, &receipt);
    audit::record_state(
        &s,
        Some(actor.id),
        "waf_retrain_config_updated",
        &serde_json::json!({ "mode": config.mode.as_str() }).to_string(),
    )
    .await;
    s.realtime.publish("waf.changed");
    match repository::get_retrain_config(&s.db).await {
        Ok(config) => Json(config).into_response(),
        Err(_) => database_error(),
    }
}

pub async fn recommendations(State(s): State<AppState>, h: HeaderMap) -> Response {
    if let Err(response) = require_role_admin(&s, &h).await {
        return response;
    }
    match pending(&s).await {
        Ok((_, recs)) => Json(recs).into_response(),
        Err(_) => database_error(),
    }
}

/// Apply current recommendations now (any mode except off).
pub async fn run(State(s): State<AppState>, h: HeaderMap) -> Response {
    let actor = match require_role_admin(&s, &h).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let mode = match repository::get_retrain_config(&s.db).await {
        Ok(config) => config.mode,
        Err(_) => return database_error(),
    };
    if mode == RetrainMode::Off {
        return user_error(
            StatusCode::CONFLICT,
            "retrain_disabled",
            "Retraining is off",
        );
    }
    match apply(&s, super::command_actor(&actor), Some(actor.id), "manual").await {
        Ok(applied) => Json(applied).into_response(),
        Err(response) => response,
    }
}

pub async fn list_tunings(State(s): State<AppState>, h: HeaderMap) -> Response {
    if let Err(response) = require_role_admin(&s, &h).await {
        return response;
    }
    match repository::list_rule_tunings(&s.db).await {
        Ok(tunings) => Json(tunings).into_response(),
        Err(_) => database_error(),
    }
}

/// Undo a demotion: restore the rule's previous action or re-enable the
/// SecLang rule.
pub async fn revert_tuning(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(rule_id): Path<i64>,
) -> Response {
    let actor = match require_role_admin(&s, &h).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(tunings) = repository::list_rule_tunings(&s.db).await else {
        return database_error();
    };
    let Some(tuning) = tunings.into_iter().find(|t| t.rule_id == rule_id) else {
        return user_error(StatusCode::NOT_FOUND, "not_found", "Tuning not found");
    };
    if tuning.kind == "waf_rule" {
        let action = match tuning.previous_action.as_deref() {
            Some("allow") => WafAction::Allow,
            Some("block") => WafAction::Block,
            Some("log") => WafAction::Log,
            _ => WafAction::Inherit,
        };
        if repository::set_waf_rule_action(&s.db, rule_id, action)
            .await
            .is_err()
        {
            return database_error();
        }
    } else {
        let Ok(mut seclang) = repository::get_seclang_config(&s.db).await else {
            return database_error();
        };
        seclang.disabled_rule_ids.retain(|id| *id != rule_id);
        if repository::update_seclang_config(&s.db, &seclang)
            .await
            .is_err()
        {
            return database_error();
        }
    }
    if repository::delete_rule_tuning(&s.db, rule_id)
        .await
        .is_err()
        || s.waf.reload(&s.db).await.is_err()
    {
        return database_error();
    }
    let (command, receipt) = match submit_policy_state_as(&s, super::command_actor(&actor)).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    publish_committed_command(&s, &command, &receipt);
    audit::record_state(
        &s,
        Some(actor.id),
        "waf_retrain_reverted",
        &serde_json::json!({ "rule_id": rule_id }).to_string(),
    )
    .await;
    s.realtime.publish("waf.changed");
    StatusCode::NO_CONTENT.into_response()
}
