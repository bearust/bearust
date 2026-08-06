//! Off-hot-path delivery of WAF-block events to an optional plugin sink.
use crate::observability::PluginMetrics;
use crate::plugin_runtime::PluginManager;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Bounded queue capacity between the proxy request path and the
/// notification worker. A full queue drops the newest event rather than
/// blocking the sender; see `NotificationSink::notify_waf_block`.
const QUEUE_CAPACITY: usize = 256;

/// Delivers WAF-block events to at most one registered `notify.waf_block`
/// plugin, off the proxy's request path. `notify_waf_block` never blocks
/// and never fails visibly to the caller: a full queue drops the event and
/// increments a metric instead.
pub struct NotificationSink {
    sender: mpsc::Sender<bearust_plugin_sdk::WafBlockEvent>,
    metrics: Arc<PluginMetrics>,
}

impl NotificationSink {
    /// Spawns the background worker and returns the handle the proxy holds
    /// for the process lifetime. The worker task owns the receiving half of
    /// the channel and outlives every individual request.
    pub fn spawn(manager: Arc<PluginManager>) -> Arc<Self> {
        let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
        let metrics = manager.metrics();
        tokio::spawn(Self::run(manager, receiver, Arc::clone(&metrics)));
        Arc::new(Self { sender, metrics })
    }

    /// Enqueues `event` for delivery. Never blocks: if the queue is full,
    /// the event is dropped and `notify_queue_dropped_total` is
    /// incremented.
    pub fn notify_waf_block(&self, event: bearust_plugin_sdk::WafBlockEvent) {
        if self.sender.try_send(event).is_err() {
            self.metrics.record_notify_dropped();
        }
    }

    async fn run(
        manager: Arc<PluginManager>,
        mut receiver: mpsc::Receiver<bearust_plugin_sdk::WafBlockEvent>,
        metrics: Arc<PluginMetrics>,
    ) {
        while let Some(event) = receiver.recv().await {
            Self::deliver(&manager, &metrics, &event);
        }
    }

    /// Delivers one event to the currently registered sink plugin, if any.
    /// No sink registered is not an error: the event is simply discarded.
    /// A plugin-side failure (trap, timeout, fuel exhaustion, malformed
    /// export, or a nonzero self-reported status) is counted and never
    /// retried or propagated.
    fn deliver(
        manager: &PluginManager,
        metrics: &PluginMetrics,
        event: &bearust_plugin_sdk::WafBlockEvent,
    ) {
        let Some(plugin) = manager.waf_block_sink_plugin() else {
            return;
        };
        match plugin.notify_waf_block(event) {
            Ok(0) => metrics.record_notify_invocation(),
            Ok(_) => metrics.record_notify_failure(),
            Err(_) => metrics.record_notify_failure(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PluginConfig;
    use std::fs;
    use tempfile::tempdir;

    fn manager_with_notify_sink_fixture(enabled: bool) -> Arc<PluginManager> {
        let root = tempdir().unwrap();
        let plugin = root.path().join("notify-sink-v2");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("plugin.toml"),
            include_str!("../tests/fixtures/plugins/notify_sink_v2/plugin.toml"),
        )
        .unwrap();
        let module = wat::parse_str(include_str!(
            "../tests/fixtures/plugins/notify_sink_v2/notify_sink_v2.wat"
        ))
        .unwrap();
        fs::write(plugin.join("notify_sink_v2.wasm"), &module).unwrap();

        let manager = PluginManager::new(PluginConfig {
            enabled: true,
            directory: root.path().to_path_buf(),
            ..PluginConfig::default()
        });
        manager.reload_from_disk().unwrap();
        if !enabled {
            manager.set_enabled("notify-sink-v2", false).unwrap();
        }
        manager
    }

    fn sample_event() -> bearust_plugin_sdk::WafBlockEvent {
        bearust_plugin_sdk::WafBlockEvent {
            request_id: "req-1".into(),
            occurred_at_ms: 1_700_000_000_000,
            category: "sqli".into(),
            score: 42,
            severity: "high".into(),
            reason_ids: "sqli".into(),
        }
    }

    #[test]
    fn deliver_invokes_the_registered_sink_and_records_success() {
        let manager = manager_with_notify_sink_fixture(true);
        let metrics = manager.metrics();
        NotificationSink::deliver(&manager, &metrics, &sample_event());
        let output = metrics.render_prometheus();
        assert!(output.contains("bearust_plugins_notify_invocations_total 1"));
        assert!(output.contains("bearust_plugins_notify_failures_total 0"));
    }

    #[test]
    fn deliver_is_a_no_op_when_no_sink_is_registered() {
        let manager = PluginManager::new(PluginConfig::default());
        let metrics = manager.metrics();
        NotificationSink::deliver(&manager, &metrics, &sample_event());
        let output = metrics.render_prometheus();
        assert!(output.contains("bearust_plugins_notify_invocations_total 0"));
        assert!(output.contains("bearust_plugins_notify_failures_total 0"));
    }

    #[test]
    fn deliver_counts_a_disabled_sink_as_no_sink_registered() {
        let manager = manager_with_notify_sink_fixture(false);
        let metrics = manager.metrics();
        NotificationSink::deliver(&manager, &metrics, &sample_event());
        let output = metrics.render_prometheus();
        assert!(output.contains("bearust_plugins_notify_invocations_total 0"));
    }

    #[test]
    fn deliver_counts_a_nonzero_plugin_status_as_a_failure_not_a_host_error() {
        let root = tempdir().unwrap();
        let plugin = root.path().join("notify-sink-v2");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("plugin.toml"),
            include_str!("../tests/fixtures/plugins/notify_sink_v2/plugin.toml"),
        )
        .unwrap();
        // Same shape as the checked-in fixture, but always reports failure.
        let wat = r#"(module
            (memory (export "memory") 1)
            (global $heap_ptr (mut i32) (i32.const 1024))
            (func (export "bearust_abi_version") (result i32) i32.const 2)
            (func (export "bearust_alloc") (param $len i32) (result i32)
                (local $ptr i32)
                global.get $heap_ptr
                local.set $ptr
                global.get $heap_ptr
                local.get $len
                i32.add
                global.set $heap_ptr
                local.get $ptr)
            (func (export "bearust_dealloc") (param i32 i32) nop)
            (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0)
            (func (export "bearust_notify_waf_block") (param i32 i32) (result i32) i32.const 1))"#;
        let module = wat::parse_str(wat).unwrap();
        fs::write(plugin.join("notify_sink_v2.wasm"), &module).unwrap();

        let manager = PluginManager::new(PluginConfig {
            enabled: true,
            directory: root.path().to_path_buf(),
            ..PluginConfig::default()
        });
        manager.reload_from_disk().unwrap();
        let metrics = manager.metrics();
        NotificationSink::deliver(&manager, &metrics, &sample_event());
        let output = metrics.render_prometheus();
        assert!(output.contains("bearust_plugins_notify_invocations_total 0"));
        assert!(output.contains("bearust_plugins_notify_failures_total 1"));
    }

    #[test]
    fn notify_waf_block_drops_the_event_and_counts_it_when_the_queue_is_full() {
        let (sender, _receiver) = mpsc::channel(1);
        let metrics = Arc::new(PluginMetrics::default());
        let sink = NotificationSink {
            sender,
            metrics: Arc::clone(&metrics),
        };
        sink.notify_waf_block(sample_event());
        sink.notify_waf_block(sample_event());
        let output = metrics.render_prometheus();
        assert!(output.contains("bearust_plugins_notify_dropped_total 1"));
    }
}
