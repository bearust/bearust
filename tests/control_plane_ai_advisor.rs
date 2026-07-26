mod support;

use bearust::ai_advisor::{
    AdvisorErrorCode, AdvisorJobId, AdvisorJobStatus, AdvisorWorkflow, RedactedValue, Redactor,
};
use bearust::control_plane::{rbac::Permission, repository};
use chrono::{Duration, Utc};
use futures_util::FutureExt;
use std::panic::AssertUnwindSafe;

async fn pool() -> repository::DbPool {
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&pool).await.unwrap();
    pool
}

fn redacted(value: &str) -> RedactedValue {
    Redactor::default().redact(&serde_json::from_str(value).unwrap())
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
