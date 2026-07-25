mod support;

use bearust::ai_advisor::{AdvisorErrorCode, AdvisorJobId, AdvisorJobStatus, AdvisorWorkflow};
use bearust::control_plane::{rbac::Permission, repository};
use chrono::{Duration, Utc};

async fn pool() -> repository::DbPool {
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&pool).await.unwrap();
    pool
}

fn job(id: &str, owner_id: i64, workflow: AdvisorWorkflow) -> repository::NewAdvisorJob {
    let now = Utc::now();
    repository::NewAdvisorJob {
        job_id: AdvisorJobId(id.into()),
        owner_id,
        workflow,
        redacted_input: r#"{\"message\":\"[REDACTED]\"}"#.into(),
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
        Some(r#"{\"draft\":\"safe\"}"#),
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
    pool.close().await;
}
