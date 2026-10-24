//! Request-body, response-header, streaming, and compressed-body transform
//! hooks, exercised through the shared helpers the HTTP/1-2 and HTTP/3
//! paths both call.

use bearust::config::PluginConfig;
use bearust::plugin_runtime::PluginManager;
use bearust::proxy;
use std::io::{Read, Write};
use std::sync::Arc;

fn manager(fixtures: &[&str]) -> (tempfile::TempDir, Arc<PluginManager>) {
    let root = tempfile::tempdir().unwrap();
    for name in fixtures {
        let source = std::path::Path::new("tests/fixtures/plugins").join(name);
        let target = root.path().join(name.replace('_', "-"));
        std::fs::create_dir_all(&target).unwrap();
        std::fs::copy(source.join("plugin.toml"), target.join("plugin.toml")).unwrap();
        let wat = std::fs::read_to_string(source.join(format!("{name}.wat"))).unwrap();
        std::fs::write(
            target.join(format!("{name}.wasm")),
            wat::parse_str(&wat).unwrap(),
        )
        .unwrap();
    }
    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        max_output_bytes: 2 * 1024 * 1024,
        ..PluginConfig::default()
    });
    let summary = manager.reload_from_disk().unwrap();
    assert_eq!(summary.failed, 0);
    (root, manager)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_body_transform_replaces_bounded_identity_bodies() {
    let (_root, manager) = manager(&["transform_request_body_v2"]);
    let m = Some(&manager);
    assert!(proxy::request_body_transform_eligible(
        m,
        Some("5"),
        None,
        false
    ));
    assert!(!proxy::request_body_transform_eligible(
        m,
        Some("0"),
        None,
        false
    ));
    assert!(!proxy::request_body_transform_eligible(
        m,
        Some("5"),
        Some("gzip"),
        false
    ));
    assert!(!proxy::request_body_transform_eligible(
        m,
        Some("2000000"),
        None,
        false
    ));
    assert!(proxy::request_body_transform_eligible(m, None, None, true));
    let out =
        proxy::apply_request_body_plugin(m, "POST", "/x", "text/plain", b"hello".to_vec()).await;
    assert_eq!(out, b"transformed");
    // No plugin: unchanged.
    assert_eq!(
        proxy::apply_request_body_plugin(None, "POST", "/", "", b"a".to_vec()).await,
        b"a"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_header_transform_keeps_framing_headers() {
    let (_root, manager) = manager(&["transform_response_headers_v2"]);
    let next = proxy::apply_response_headers_plugin(
        Some(&manager),
        200,
        vec![
            ("content-type".into(), "text/html".into()),
            ("content-length".into(), "42".into()),
            ("content-encoding".into(), "gzip".into()),
        ],
    )
    .await
    .unwrap();
    assert!(next.contains(&("x-plugin".into(), "yes".into())));
    // The plugin's content-length is ignored; the upstream's is restored.
    assert!(next.contains(&("content-length".into(), "42".into())));
    assert!(!next.contains(&("content-length".into(), "1".into())));
    assert!(next.contains(&("content-encoding".into(), "gzip".into())));
    assert!(!next.iter().any(|(n, _)| n == "content-type"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_transform_handles_each_slice() {
    let (_root, manager) = manager(&["transform_response_stream_v2"]);
    let m = Some(&manager);
    assert!(proxy::response_stream_transform_eligible(
        m,
        false,
        http::StatusCode::OK,
        None
    ));
    assert!(!proxy::response_stream_transform_eligible(
        m,
        true,
        http::StatusCode::OK,
        None
    ));
    assert!(!proxy::response_stream_transform_eligible(
        m,
        false,
        http::StatusCode::OK,
        Some("br")
    ));
    let mut index = 0;
    // 150 KiB -> three 64 KiB-or-less slices, each replaced by "X".
    let out = tokio::task::block_in_place(|| {
        proxy::apply_stream_chunk_plugin(m, 200, &mut index, &vec![b'a'; 150 * 1024], false)
    });
    assert_eq!((out.as_slice(), index), (&b"XXX"[..], 3));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compressed_bodies_are_decoded_transformed_and_reencoded() {
    let (_root, manager) = manager(&["transform_response_v2"]);
    let m = Some(&manager);
    for encoding in ["gzip", "deflate"] {
        assert!(proxy::response_transform_eligible(
            m,
            false,
            http::StatusCode::OK,
            None,
            Some(encoding)
        ));
        let compressed = proxy::encode_body(encoding, b"original body").unwrap();
        let out = tokio::task::block_in_place(|| {
            proxy::apply_transform_response_encoded(m, 200, Some(encoding), compressed)
        });
        assert_eq!(
            proxy::decode_body(encoding, &out, 1024).unwrap(),
            b"hello",
            "{encoding}"
        );
    }
    assert!(!proxy::response_transform_eligible(
        m,
        false,
        http::StatusCode::OK,
        None,
        Some("br")
    ));
    // A decompression bomb exceeds the cap and passes through untouched.
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(&vec![0u8; 4 * 1024 * 1024]).unwrap();
    let bomb = encoder.finish().unwrap();
    let out = tokio::task::block_in_place(|| {
        proxy::apply_transform_response_encoded(m, 200, Some("gzip"), bomb.clone())
    });
    assert_eq!(out, bomb);
    let mut check = Vec::new();
    flate2::read::GzDecoder::new(out.as_slice())
        .read_to_end(&mut check)
        .unwrap();
}
