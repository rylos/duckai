mod client;
mod model;
mod route;
mod signal;

use crate::{config::Config, error::Error, Result};
use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use axum_extra::headers::{authorization::Bearer, Authorization};
use axum_extra::TypedHeader;
use axum_server::{tls_rustls::RustlsConfig, Handle};
use client::{build_client, HttpConfig};
use hyper_util::rt::TokioTimer;
use reqwest::Client;
use serde::Serialize;
use std::{ops::Deref, path::PathBuf, sync::Arc, time::Duration};
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};
use tracing::Level;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use typed_builder::TypedBuilder;

#[derive(Clone, TypedBuilder)]
pub struct AppState {
    client: Client,
    api_key: Arc<Option<String>>,
}

impl Deref for AppState {
    type Target = Client;
    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl AppState {
    pub fn valid_key(
        &self,
        bearer: Option<TypedHeader<Authorization<Bearer>>>,
    ) -> crate::Result<()> {
        let api_key = bearer.as_deref().map(|b| b.token());
        if let Some(key) = self.api_key.as_deref() {
            if Some(key) != api_key {
                return Err(crate::Error::InvalidApiKey);
            }
        }
        Ok(())
    }
}

#[tokio::main]
pub async fn run(path: PathBuf) -> Result<()> {
    // init config
    let config = init_config(path).await?;

    // init logger
    init_logger(config.debug)?;

    // init boot message
    boot_message(&config);

    // init global layer provider
    let global_layer = tower::ServiceBuilder::new().layer(
        CorsLayer::new()
            .allow_credentials(true)
            .allow_headers(AllowHeaders::mirror_request())
            .allow_methods(AllowMethods::mirror_request())
            .allow_origin(AllowOrigin::mirror_request()),
    );

    let http_config = HttpConfig::builder()
        .timeout(config.timeout)
        .connect_timeout(config.connect_timeout)
        .tcp_keepalive(config.tcp_keepalive)
        .build();

    let app_state = AppState::builder()
        .client(build_client(http_config).await)
        .api_key(Arc::new(config.api_key))
        .build();

    let router = Router::new()
        .route("/v1/models", get(route::models))
        .route("/v1/chat/completions", post(route::chat_completions))
        .with_state(app_state)
        .layer(global_layer);

    // Signal the server to shutdown using Handle.
    let handle = Handle::new();

    // Spawn a task to gracefully shutdown server.
    tokio::spawn(signal::graceful_shutdown(handle.clone()));

    // http server tcp keepalive
    let tcp_keepalive = config.tcp_keepalive.map(Duration::from_secs);

    // Run http server
    match (config.tls_cert.as_ref(), config.tls_key.as_ref()) {
        (Some(cert), Some(key)) => {
            // Load TLS configuration
            let tls_config = RustlsConfig::from_pem_file(cert, key).await?;

            // Use TLS configuration to create a secure server
            let mut server = axum_server::bind_rustls(config.bind, tls_config);
            server
                .http_builder()
                .http1()
                .preserve_header_case(true)
                .http2()
                .timer(TokioTimer::new())
                .keep_alive_interval(tcp_keepalive);

            server
                .handle(handle)
                .serve(router.into_make_service())
                .await
        }
        _ => {
            // No TLS configuration, create a non-secure server
            let mut server = axum_server::bind(config.bind);
            server
                .http_builder()
                .http1()
                .preserve_header_case(true)
                .http2()
                .keep_alive_interval(tcp_keepalive);

            server
                .handle(handle)
                .serve(router.into_make_service())
                .await
        }
    }
    .map_err(Into::into)
}

fn boot_message(config: &Config) {
    tracing::info!("Bind address: {}", config.bind);
}

/// Initialize the logger with a filter that ignores WARN level logs for netlink_proto
fn init_logger(debug: bool) -> Result<()> {
    let filter = EnvFilter::from_default_env()
        .add_directive(if debug { Level::DEBUG } else { Level::INFO }.into())
        .add_directive("netlink_proto=error".parse()?);
    tracing::subscriber::set_global_default(
        FmtSubscriber::builder().with_env_filter(filter).finish(),
    )?;
    Ok(())
}

/// Init configuration
async fn init_config(path: PathBuf) -> Result<Config> {
    if !path.is_file() {
        Ok(Config::default())
    } else {
        let data = tokio::fs::read(path).await?;
        serde_yaml::from_slice::<Config>(&data).map_err(Into::into)
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        #[derive(Serialize, TypedBuilder)]
        struct ResponseError {
            message: String,
            #[serde(rename = "type")]
            type_field: &'static str,
            #[builder(default)]
            param: Option<String>,
        }

        match self {
            Error::JsonExtractorRejection(json_rejection) => (
                StatusCode::BAD_REQUEST,
                Json(
                    ResponseError::builder()
                        .message(json_rejection.body_text())
                        .type_field("invalid_request_error")
                        .build(),
                ),
            )
                .into_response(),
            Error::InvalidApiKey => (
                StatusCode::UNAUTHORIZED,
                Json(
                    ResponseError::builder()
                        .message(self.to_string())
                        .type_field("invalid_request_error")
                        .build(),
                ),
            )
                .into_response(),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    ResponseError::builder()
                        .message(self.to_string())
                        .type_field("server_error")
                        .build(),
                ),
            )
                .into_response(),
        }
    }
}
