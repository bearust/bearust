//! Feedback-driven WAF rule retraining.
//!
//! Operators label WAF detections as false or true positives. Rules whose
//! recent feedback is overwhelmingly false-positive are demoted: Bearust
//! rules switch to log-only, CRS/SecLang rules are excluded by id. In
//! `recommend` mode this only produces recommendations; in `enforce` mode
//! they are applied (audited, reversible). Demotions are never undone
//! automatically: re-enabling a rule is an operator decision.

use crate::control_plane::models::WafFeedback;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RetrainMode {
    #[default]
    Off,
    Recommend,
    Enforce,
}

impl RetrainMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Recommend => "recommend",
            Self::Enforce => "enforce",
        }
    }
    pub fn parse(value: &str) -> Self {
        match value {
            "recommend" => Self::Recommend,
            "enforce" => Self::Enforce,
            _ => Self::Off,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrainConfig {
    pub mode: RetrainMode,
    /// False-positive reports needed before a rule is considered.
    pub min_reports: u32,
    /// Minimum share of false positives among labeled reports, in percent.
    pub false_positive_percent: u8,
    /// Only feedback from the last `window_days` counts.
    pub window_days: u32,
    #[serde(default)]
    pub updated_at: String,
}

impl Default for RetrainConfig {
    fn default() -> Self {
        Self {
            mode: RetrainMode::Off,
            min_reports: 5,
            false_positive_percent: 80,
            window_days: 30,
            updated_at: String::new(),
        }
    }
}

impl RetrainConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(1..=10_000).contains(&self.min_reports)
            || !(50..=100).contains(&self.false_positive_percent)
            || !(1..=365).contains(&self.window_days)
        {
            return Err("invalid retraining settings");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recommendation {
    pub rule_id: i64,
    pub false_positives: u32,
    pub true_positives: u32,
}

/// Rules that qualify for demotion, most false positives first. `exclude`
/// lists rule ids already demoted.
pub fn recommend(
    feedback: &[WafFeedback],
    config: &RetrainConfig,
    now: chrono::DateTime<chrono::Utc>,
    exclude: &[i64],
) -> Vec<Recommendation> {
    let since = now - chrono::Duration::days(i64::from(config.window_days));
    let mut counts: BTreeMap<i64, (u32, u32)> = BTreeMap::new();
    for item in feedback {
        let Some(rule_id) = item.rule_id else {
            continue;
        };
        let recent =
            chrono::DateTime::parse_from_rfc3339(&item.created_at).is_ok_and(|at| at >= since);
        if !recent {
            continue;
        }
        let entry = counts.entry(rule_id).or_default();
        match item.label.as_str() {
            "false_positive" => entry.0 += 1,
            "true_positive" => entry.1 += 1,
            _ => {}
        }
    }
    let mut out: Vec<_> = counts
        .into_iter()
        .filter(|(rule_id, (fp, tp))| {
            !exclude.contains(rule_id)
                && *fp >= config.min_reports
                && u64::from(*fp) * 100
                    >= u64::from(config.false_positive_percent) * u64::from(fp + tp)
        })
        .map(|(rule_id, (fp, tp))| Recommendation {
            rule_id,
            false_positives: fp,
            true_positives: tp,
        })
        .collect();
    out.sort_by(|a, b| {
        b.false_positives
            .cmp(&a.false_positives)
            .then(a.rule_id.cmp(&b.rule_id))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fb(rule_id: i64, label: &str, days_ago: i64) -> WafFeedback {
        WafFeedback {
            id: 0,
            reporter_id: None,
            request_id: None,
            rule_id: Some(rule_id),
            label: label.into(),
            note: String::new(),
            created_at: (chrono::Utc::now() - chrono::Duration::days(days_ago)).to_rfc3339(),
        }
    }

    #[test]
    fn demotes_only_rules_with_enough_recent_overwhelming_false_positives() {
        let mut feedback = Vec::new();
        feedback.extend((0..6).map(|_| fb(942100, "false_positive", 1)));
        feedback.push(fb(942100, "true_positive", 1));
        // Many FPs but also many TPs: ratio too low.
        feedback.extend((0..6).map(|_| fb(941100, "false_positive", 1)));
        feedback.extend((0..6).map(|_| fb(941100, "true_positive", 1)));
        // Too few reports.
        feedback.extend((0..3).map(|_| fb(930100, "false_positive", 1)));
        // Outside the window.
        feedback.extend((0..9).map(|_| fb(920100, "false_positive", 60)));
        let config = RetrainConfig::default();
        let recs = recommend(&feedback, &config, chrono::Utc::now(), &[]);
        assert_eq!(
            recs,
            vec![Recommendation {
                rule_id: 942100,
                false_positives: 6,
                true_positives: 1
            }]
        );
        assert!(recommend(&feedback, &config, chrono::Utc::now(), &[942100]).is_empty());
    }
}
