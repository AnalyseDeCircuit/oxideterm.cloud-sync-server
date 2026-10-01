// Copyright (C) 2026 AnalyseDeCircuit. Licensed under AGPL-3.0-or-later.

use super::*;
use axum::body::{to_bytes, Body};
use axum::http::Request;
use serde_json::Value;
use tower::ServiceExt;

async fn request(app: &Router, method: Method, uri: &str, token: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", format!("Bearer {token}"))
                .extension(ConnectInfo(
                    "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
                ))
                .body(Body::from("encrypted-client-snapshot"))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn json_body(response: axum::response::Response) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap()
}

#[tokio::test]
async fn object_discovery_and_cleanup_respect_namespace_and_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sync.redb");
    let db = Database::open(path.to_str().unwrap()).unwrap();
    for (name, permissions) in [
        ("writer", vec!["read".into(), "write".into()]),
        ("reader", vec!["read".into()]),
    ] {
        db.set_token(&ApiToken {
            id: name.into(),
            name: name.into(),
            token_hash: auth::hash_api_token(name),
            encrypted_token: None,
            namespace_pattern: "demo*".into(),
            permissions,
            created_at: chrono::Utc::now().to_rfc3339(),
            enabled: true,
            expires_at: None,
            rotated_at: None,
            disabled_at: None,
            last_used_at: None,
            device_id: None,
            read_count: 0,
            write_count: 0,
            failed_count: 0,
            last_namespace: None,
            last_permission: None,
            last_client_ip: None,
            last_client_version: None,
        })
        .unwrap();
    }
    let app = router(AppState {
        db: db.clone(),
        db_path: path.to_string_lossy().into_owned(),
        encryption_key: Some([7; 32]),
        admin_enabled: false,
        jwt_secret: "test-secret".into(),
        admin_jwt_secret_persistent: true,
        admin_cookie_secure: true,
        token_reveal_key: [0; 32],
        token_reveal_persistent: true,
        trust_proxy_headers: false,
        sync_cors_allowed_origins: vec!["*".into()],
        max_blob_size: 1024,
        max_object_size: 1024,
        min_free_disk_bytes: 0,
        login_window_seconds: 900,
        login_lockout_seconds: 900,
        max_login_failures: 5,
        token_usage_write_interval_seconds: 60,
        usage_refresh_interval_seconds: 60,
        max_sync_conflict_records: 500,
        default_token_ttl_seconds: None,
        metadata_retention: MetadataRetentionConfig {
            store_revision: true,
            store_uploaded_at: true,
            store_device_id: true,
            store_content_hash: true,
        },
    });
    let base = "/v1/namespaces/demo/objects";
    assert_eq!(
        json_body(request(&app, Method::GET, base, "writer").await).await,
        json!({"objects": [], "nextCursor": null})
    );
    for (namespace, object) in [
        ("demo", "sync-v3/b.oxide"),
        ("demo", "sync-v3/a.oxide"),
        ("demo", "legacy.json"),
        ("demo-other", "sync-v3/foreign.oxide"),
    ] {
        let uri = format!("/v1/namespaces/{namespace}/objects/{object}");
        assert_eq!(
            request(&app, Method::PUT, &uri, "writer").await.status(),
            StatusCode::OK
        );
    }
    assert_eq!(db.list_namespaces().unwrap(), vec!["demo", "demo-other"]);
    let first = json_body(
        request(
            &app,
            Method::GET,
            &format!("{base}?prefix=sync-v3/&limit=1"),
            "reader",
        )
        .await,
    )
    .await;
    assert_eq!(first["objects"], json!([{"path": "sync-v3/a.oxide"}]));
    let cursor = urlencoding::encode(first["nextCursor"].as_str().unwrap());
    let second = json_body(
        request(
            &app,
            Method::GET,
            &format!("{base}?prefix=sync-v3/&limit=1&cursor={cursor}"),
            "reader",
        )
        .await,
    )
    .await;
    assert_eq!(
        second,
        json!({"objects": [{"path": "sync-v3/b.oxide"}], "nextCursor": null})
    );
    for method in [Method::GET, Method::DELETE] {
        let suffix = if method == Method::GET {
            ""
        } else {
            "/sync-v3/a.oxide"
        };
        assert_eq!(
            request(&app, method.clone(), &format!("{base}{suffix}"), "invalid")
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request(
                &app,
                method,
                &format!("/v1/namespaces/private/objects{suffix}"),
                "writer"
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
    }
    let object_uri = format!("{base}/sync-v3/a.oxide");
    assert_eq!(
        request(&app, Method::DELETE, &object_uri, "reader")
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let response = request(&app, Method::GET, &object_uri, "reader").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap().as_ref(),
        b"encrypted-client-snapshot"
    );
    for _ in 0..2 {
        assert_eq!(
            request(&app, Method::DELETE, &object_uri, "writer")
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
    }
    assert_eq!(
        request(&app, Method::GET, &object_uri, "reader")
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert!(db
        .get_object_metadata("demo", "sync-v3/a.oxide")
        .unwrap()
        .is_none());
    assert_eq!(
        json_body(
            request(
                &app,
                Method::GET,
                &format!("{base}?prefix=sync-v3/"),
                "reader"
            )
            .await
        )
        .await,
        json!({"objects": [{"path": "sync-v3/b.oxide"}], "nextCursor": null})
    );
    for query in ["limit=0", "limit=257", "prefix=sync-v3/&cursor=legacy.json"] {
        assert_eq!(
            request(&app, Method::GET, &format!("{base}?{query}"), "reader")
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    db.soft_delete_namespace("demo", &chrono::Utc::now().to_rfc3339())
        .unwrap();
    assert_eq!(
        request(&app, Method::GET, base, "reader").await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(&app, Method::DELETE, &object_uri, "writer")
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(db.list_namespaces().unwrap(), vec!["demo-other"]);
}
