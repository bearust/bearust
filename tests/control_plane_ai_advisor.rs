mod support;

use bearust::ai_advisor::{AdvisorErrorCode, AdvisorJobId, AdvisorJobStatus, AdvisorWorkflow};
use bearust::control_plane::{rbac::Permission, repository};
use chrono::{Duration, Utc};

async fn pool() -> repository::DbPool {
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&pool).await.unwrap();
    pool
}

fn job(_id: &str, owner_id: i64, workflow: AdvisorWorkflow) -> repository::NewAdvisorJob {
    let now = Utc::now();
    repository::NewAdvisorJob {
        job_id: AdvisorJobId::new(),
        owner_id,
        workflow,
        redacted_input: r#"{"message":"[REDACTED]"}"#.into(),
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
    let admin = repository::role_by_slug(&pool, "admin")
        .await
        .unwrap()
        .unwrap();
    assert!(repository::role_permissions(&pool, admin.id)
        .await
        .unwrap()
        .contains(&"ai_advisor.approve".to_owned()));
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
        Some(r#"{"message":"safe"}"#),
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
    assert_eq!(decided.draft_decision.as_deref(), Some("approved"));
    assert!(decided.draft_decided_at.is_some());
}

#[tokio::test]
async fn advisor_repository_rejects_oversized_persistence_and_expires_jobs() {
    let pool = pool().await;
    let mut oversized = job("job-oversized", 7, AdvisorWorkflow::IncidentExplanation);
    oversized.redacted_input = "x".repeat(repository::MAX_ADVISOR_PERSISTED_BYTES + 1);
    assert!(repository::insert_advisor_job(&pool, &oversized)
        .await
        .is_err());

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
    raw.redacted_input =
        r#"{"message":"Authorization: Bearer secret","body":"password=hunter2"}"#.into();
    assert!(repository::insert_advisor_job(&pool, &raw).await.is_err());
    let mut invalid = job("not-a-uuid", 7, AdvisorWorkflow::IncidentExplanation);
    invalid.job_id = AdvisorJobId("not-a-uuid".into());
    assert!(repository::insert_advisor_job(&pool, &invalid)
        .await
        .is_err());
    invalid.job_id = AdvisorJobId::new();
    invalid.config_hash = "z".repeat(64);
    assert!(repository::insert_advisor_job(&pool, &invalid)
        .await
        .is_err());
    let valid = job(
        &AdvisorJobId::new().0,
        7,
        AdvisorWorkflow::IncidentExplanation,
    );
    assert!(repository::insert_advisor_job(&pool, &valid).await.is_ok());
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
async fn advisor_jobs_paginate_by_owner_newest_first() {
    let pool = pool().await;
    for id in ["job-page-1", "job-page-2", "job-page-3"] {
        repository::insert_advisor_job(&pool, &job(id, 7, AdvisorWorkflow::SecuritySummary))
            .await
            .unwrap();
    }
    repository::insert_advisor_job(
        &pool,
        &job("other-owner", 8, AdvisorWorkflow::SecuritySummary),
    )
    .await
    .unwrap();
    let page = repository::list_advisor_jobs(&pool, 7, 2, 2).await.unwrap();
    assert_eq!(page.total, 3);
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].owner_id, 7);
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
    let inserted = repository::insert_advisor_job(
        &pool,
        &job(
            &AdvisorJobId::new().0,
            1,
            AdvisorWorkflow::IncidentExplanation,
        ),
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
        Some(r#"{"message":"ok"}"#),
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
        repository::list_advisor_jobs(&pool, 1, 1, 10)
            .await
            .unwrap()
            .total,
        1
    );
    let draft = repository::insert_advisor_job(
        &pool,
        &job(
            &AdvisorJobId::new().0,
            1,
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
        Some(r#"{"message":"draft"}"#),
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
    pool.close().await;
}
