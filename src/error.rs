// Copyright (C) 2026 AnalyseDeCircuit. Licensed under AGPL-3.0-or-later.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    Conflict {
        code: String,
        message: String,
        remote_revision: Option<String>,
        remote_etag: Option<String>,
    },
    PayloadTooLarge(String),
    TooManyRequests(String),
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            AppError::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                json!({
                    "error": { "code": "bad_request", "message": msg }
                }),
            ),
            AppError::Unauthorized(msg) => (
                StatusCode::UNAUTHORIZED,
                json!({
                    "error": { "code": "unauthorized", "message": msg }
                }),
            ),
            AppError::Forbidden(msg) => (
                StatusCode::FORBIDDEN,
                json!({
                    "error": { "code": "forbidden", "message": msg }
                }),
            ),
            AppError::NotFound(msg) => (
                StatusCode::NOT_FOUND,
                json!({
                    "error": { "code": "not_found", "message": msg }
                }),
            ),
            AppError::Conflict {
                code,
                message,
                remote_revision,
                remote_etag,
            } => (
                StatusCode::PRECONDITION_FAILED,
                json!({
                    "ok": false,
                    "error": {
                        "code": code,
                        "message": message,
                        "remoteRevision": remote_revision,
                        "remoteEtag": remote_etag
                    }
                }),
            ),
            AppError::PayloadTooLarge(msg) => (
                StatusCode::PAYLOAD_TOO_LARGE,
                json!({
                    "error": { "code": "payload_too_large", "message": msg }
                }),
            ),
            AppError::TooManyRequests(msg) => (
                StatusCode::TOO_MANY_REQUESTS,
                json!({
                    "error": { "code": "too_many_requests", "message": msg }
                }),
            ),
            AppError::Internal(msg) => {
                tracing::error!("Internal error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({
                        "error": { "code": "internal_error", "message": "Internal server error" }
                    }),
                )
            }
        };
        (status, axum::Json(body)).into_response()
    }
}

impl From<redb::Error> for AppError {
    fn from(e: redb::Error) -> Self {
        AppError::Internal(format!("Database error: {e}"))
    }
}

impl From<redb::DatabaseError> for AppError {
    fn from(e: redb::DatabaseError) -> Self {
        AppError::Internal(format!("Database error: {e}"))
    }
}

impl From<redb::TableError> for AppError {
    fn from(e: redb::TableError) -> Self {
        AppError::Internal(format!("Table error: {e}"))
    }
}

impl From<redb::StorageError> for AppError {
    fn from(e: redb::StorageError) -> Self {
        AppError::Internal(format!("Storage error: {e}"))
    }
}

impl From<redb::TransactionError> for AppError {
    fn from(e: redb::TransactionError) -> Self {
        AppError::Internal(format!("Transaction error: {e}"))
    }
}

impl From<redb::CommitError> for AppError {
    fn from(e: redb::CommitError) -> Self {
        AppError::Internal(format!("Commit error: {e}"))
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::BadRequest(format!("JSON error: {e}"))
    }
}
