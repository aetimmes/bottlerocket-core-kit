/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use aws_smithy_async::future::timeout::TimedOutError;
use aws_smithy_async::rt::sleep::{default_async_sleep, AsyncSleep, SharedAsyncSleep};
use aws_smithy_runtime::client::http::connection_poisoning::CaptureSmithyConnection;
use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::connection::ConnectionMetadata;
use aws_smithy_runtime_api::client::connector_metadata::ConnectorMetadata;
use aws_smithy_runtime_api::client::dns::ResolveDns;
use aws_smithy_runtime_api::client::http::{
    HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings, SharedHttpClient,
    SharedHttpConnector,
};
use aws_smithy_runtime_api::client::orchestrator::{HttpRequest, HttpResponse};
use aws_smithy_runtime_api::client::result::ConnectorError;
use aws_smithy_runtime_api::client::runtime_components::{
    RuntimeComponents, RuntimeComponentsBuilder,
};
use aws_smithy_runtime_api::shared::IntoShared;
use aws_smithy_types::body::SdkBody;
use aws_smithy_types::config_bag::ConfigBag;
use aws_smithy_types::error::display::DisplayErrorContext;
use aws_smithy_types::retry::ErrorKind;
use client::connect::Connection;
use h2::Reason;
use http::{Extensions, Uri};
use hyper::rt::{Read, Write};
use hyper_util::client::legacy as client;
use hyper_util::client::legacy::connect::dns::Name;
use hyper_util::client::legacy::connect::{
    capture_connection, CaptureConnection, Connect, HttpInfo,
};
use hyper_util::rt::TokioExecutor;
use rustls::crypto::CryptoProvider;
use std::borrow::Cow;
use std::collections::HashMap;
use std::error::Error;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::RwLock;
use std::task::{Context, Poll};
use std::time::Duration;
use std::{fmt, vec};

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[non_exhaustive]
pub enum CryptoMode {
    #[cfg(feature = "crypto-ring")]
    Ring,
    #[cfg(feature = "crypto-aws-lc")]
    AwsLc,
    #[cfg(feature = "crypto-aws-lc-fips")]
    AwsLcFips,
}

impl CryptoMode {
    fn provider(self) -> CryptoProvider {
        match self {
            #[cfg(feature = "crypto-aws-lc")]
            CryptoMode::AwsLc => rustls::crypto::aws_lc_rs::default_provider(),

            #[cfg(feature = "crypto-ring")]
            CryptoMode::Ring => rustls::crypto::ring::default_provider(),

            #[cfg(feature = "crypto-aws-lc-fips")]
            CryptoMode::AwsLcFips => {
                let provider = rustls::crypto::default_fips_provider();
                assert!(
                    provider.fips(),
                    "FIPS was requested but the provider did not support FIPS"
                );
                provider
            }
        }
    }
}

/// A bridge that allows our `ResolveDns` trait to work with Hyper's `Resolver` interface (based on tower)
#[derive(Clone)]
struct HyperUtilResolver<R> {
    resolver: R,
}

impl<R: ResolveDns + Clone + 'static> tower::Service<Name> for HyperUtilResolver<R> {
    type Response = vec::IntoIter<SocketAddr>;
    type Error = Box<dyn Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Name) -> Self::Future {
        let resolver = self.resolver.clone();
        Box::pin(async move {
            let dns_entries = resolver.resolve_dns(req.as_str()).await?;
            Ok(dns_entries
                .into_iter()
                .map(|ip_addr| SocketAddr::new(ip_addr, 0))
                .collect::<Vec<_>>()
                .into_iter())
        })
    }
}

#[allow(unused_imports)]
mod cached_connectors {
    use client::connect::HttpConnector;
    use hyper_util::client::legacy as client;
    use hyper_util::client::legacy::connect::dns::GaiResolver;

    use crate::hyper_1_0::build_connector::make_tls;
    use crate::hyper_1_0::{CryptoMode, Inner};

    #[cfg(feature = "crypto-ring")]
    pub(crate) static HTTPS_NATIVE_ROOTS_RING: once_cell::sync::Lazy<
        hyper_rustls::HttpsConnector<HttpConnector>,
    > = once_cell::sync::Lazy::new(|| make_tls(GaiResolver::new(), CryptoMode::Ring.provider()));

    #[cfg(feature = "crypto-aws-lc")]
    pub(crate) static HTTPS_NATIVE_ROOTS_AWS_LC: once_cell::sync::Lazy<
        hyper_rustls::HttpsConnector<HttpConnector>,
    > = once_cell::sync::Lazy::new(|| make_tls(GaiResolver::new(), CryptoMode::AwsLc.provider()));

    #[cfg(feature = "crypto-aws-lc-fips")]
    pub(crate) static HTTPS_NATIVE_ROOTS_AWS_LC_FIPS: once_cell::sync::Lazy<
        hyper_rustls::HttpsConnector<HttpConnector>,
    > = once_cell::sync::Lazy::new(|| {
        make_tls(GaiResolver::new(), CryptoMode::AwsLcFips.provider())
    });

    pub(super) fn cached_https(mode: Inner) -> hyper_rustls::HttpsConnector<HttpConnector> {
        match mode {
            #[cfg(feature = "crypto-ring")]
            Inner::Standard(CryptoMode::Ring) => HTTPS_NATIVE_ROOTS_RING.clone(),
            #[cfg(feature = "crypto-aws-lc")]
            Inner::Standard(CryptoMode::AwsLc) => HTTPS_NATIVE_ROOTS_AWS_LC.clone(),
            #[cfg(feature = "crypto-aws-lc-fips")]
            Inner::Standard(CryptoMode::AwsLcFips) => HTTPS_NATIVE_ROOTS_AWS_LC_FIPS.clone(),
            #[allow(unreachable_patterns)]
            Inner::Standard(_) => unreachable!("unexpected mode"),
            Inner::Custom(provider) => make_tls(GaiResolver::new(), provider),
        }
    }
}

mod build_connector {
    use crate::hyper_1_0::{HyperUtilResolver, Inner};
    use aws_smithy_runtime_api::client::dns::ResolveDns;
    use client::connect::HttpConnector;
    use headers::Authorization;
    use hyper::Uri;
    use hyper_http_proxy::{Proxy, ProxyConnector};
    use hyper_util::client::legacy as client;
    use rustls::crypto::CryptoProvider;
    use std::sync::Arc;
    use url::Url;

    fn restrict_ciphers(base: CryptoProvider) -> CryptoProvider {
        let suites = &[
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
            // TLS1.2 suites
            rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ];
        let supported_suites = suites
            .iter()
            .flat_map(|suite| {
                base.cipher_suites
                    .iter()
                    .find(|s| &s.suite() == suite)
                    .cloned()
            })
            .collect::<Vec<_>>();
        CryptoProvider {
            cipher_suites: supported_suites,
            ..base
        }
    }

    pub(crate) fn make_tls<R>(
        resolver: R,
        crypto_provider: CryptoProvider,
    ) -> hyper_rustls::HttpsConnector<HttpConnector<R>> {
        use hyper_rustls::ConfigBuilderExt;
        let mut base_connector = HttpConnector::new_with_resolver(resolver);
        base_connector.enforce_http(false);
        hyper_rustls::HttpsConnectorBuilder::new()
               .with_tls_config(
                rustls::ClientConfig::builder_with_provider(Arc::new(restrict_ciphers(crypto_provider)))
                    .with_safe_default_protocol_versions()
                    .expect("Error with the TLS configuration. Please file a bug report under https://github.com/smithy-lang/smithy-rs/issues.")
                    .with_native_roots().expect("error with TLS configuration.")
                    .with_no_client_auth()
            )
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(base_connector)
    }

    pub(super) fn https_with_resolver<R: ResolveDns>(
        crypto_provider: Inner,
        resolver: R,
    ) -> hyper_rustls::HttpsConnector<HttpConnector<HyperUtilResolver<R>>> {
        make_tls(HyperUtilResolver { resolver }, crypto_provider.provider())
    }

    pub(super) fn https_with_proxy(
        https_connector: hyper_rustls::HttpsConnector<HttpConnector>,
        https_proxy: &str,
        no_proxy: Option<Vec<String>>,
    ) -> hyper_http_proxy::ProxyConnector<hyper_rustls::HttpsConnector<HttpConnector>> {
        // Determines whether a request of a given scheme, host and port should be proxied
        // according to `https_proxy` and `no_proxy`.

        let intercept = move |scheme: Option<&str>, host: Option<&str>, _port| {
            if let Some(host) = host {
                if let Some(no_proxy) = &no_proxy {
                    if scheme != Some("https") {
                        return false;
                    }
                    if no_proxy.iter().any(|s| s == "*") {
                        // Don't proxy anything
                        return false;
                    }
                    // If the host matches one of the no proxy list entries, return false (don't proxy)
                    // Note that we're not doing anything fancy here for checking `no_proxy` since
                    // we only expect requests here to be going out to some AWS API endpoint.
                    return !no_proxy.iter().any(|no_proxy_host| {
                        !no_proxy_host.is_empty() && host.ends_with(no_proxy_host)
                    });
                }
                true
            } else {
                false
            }
        };

        let mut proxy_uri = https_proxy.parse::<Uri>().expect("Invalid proxy URI");

        // If the proxy's URI doesn't have a scheme, assume HTTP for the scheme and let the proxy
        // server forward HTTPS connections and start a tunnel.
        if proxy_uri.scheme().is_none() {
            proxy_uri = format!("http://{}", https_proxy)
                .parse::<Uri>()
                .expect("Unable to parse proxy URI as HTTPS");
        }
        let mut proxy = Proxy::new(intercept, proxy_uri);
        // Parse https_proxy as URL to extract out auth information if any
        let proxy_url =
            Url::parse(&proxy.uri().to_string()).expect("Unable to parse HTTPS proxy as URL");

        if !proxy_url.username().is_empty() || proxy_url.password().is_some() {
            proxy.set_authorization(Authorization::basic(
                proxy_url.username(),
                proxy_url.password().unwrap_or_default(),
            ));
        }
        ProxyConnector::from_proxy(https_connector, proxy)
            .expect("Failed to create proxy connector")
    }
}

/// [`HttpConnector`] that uses [`hyper`] to make HTTP requests.
///
/// This connector also implements socket connect and read timeouts.
///
/// This shouldn't be used directly in most cases.
/// See the docs on [`HyperClientBuilder`] for examples of how
/// to customize the Hyper client.
#[derive(Debug)]
pub struct HyperConnector {
    adapter: Box<dyn HttpConnector>,
}

impl HyperConnector {
    /// Builder for a Hyper connector.
    pub fn builder() -> HyperConnectorBuilder {
        Default::default()
    }
}

impl HttpConnector for HyperConnector {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        self.adapter.call(request)
    }
}

/// Builder for [`HyperConnector`].
#[derive(Default, Debug)]
pub struct HyperConnectorBuilder<Crypto = CryptoUnset> {
    connector_settings: Option<HttpConnectorSettings>,
    sleep_impl: Option<SharedAsyncSleep>,
    client_builder: Option<hyper_util::client::legacy::Builder>,
    #[allow(unused)]
    crypto: Crypto,
}

#[derive(Default)]
#[non_exhaustive]
pub struct CryptoUnset {}

pub struct CryptoProviderSelected {
    crypto_provider: Inner,
}

#[derive(Clone)]
enum Inner {
    Standard(CryptoMode),
    #[allow(dead_code)]
    Custom(CryptoProvider),
}

impl Inner {
    fn provider(&self) -> CryptoProvider {
        match self {
            Inner::Standard(mode) => mode.provider(),
            Inner::Custom(provider) => provider.clone(),
        }
    }
}

#[cfg(any(feature = "crypto-aws-lc", feature = "crypto-ring"))]
impl HyperConnectorBuilder<CryptoProviderSelected> {
    pub fn build_from_resolver<R: ResolveDns + Clone + 'static>(
        self,
        resolver: R,
    ) -> HyperConnector {
        let connector =
            build_connector::https_with_resolver(self.crypto.crypto_provider.clone(), resolver);
        self.build(connector)
    }
}

impl<Any> HyperConnectorBuilder<Any> {
    /// Create a [`HyperConnector`] from this builder and a given connector.
    pub(crate) fn build<C>(self, tcp_connector: C) -> HyperConnector
    where
        C: Send + Sync + 'static,
        C: Clone,
        C: tower::Service<Uri>,
        C::Response: Read + Write + Connection + Send + Sync + Unpin,
        C: Connect,
        C::Future: Unpin + Send + 'static,
        C::Error: Into<BoxError>,
    {
        let client_builder =
            self.client_builder
                .unwrap_or(hyper_util::client::legacy::Builder::new(
                    TokioExecutor::new(),
                ));
        let sleep_impl = self.sleep_impl.or_else(default_async_sleep);
        let (connect_timeout, read_timeout) = self
            .connector_settings
            .map(|c| (c.connect_timeout(), c.read_timeout()))
            .unwrap_or((None, None));

        let connector = match connect_timeout {
            Some(duration) => timeout_middleware::ConnectTimeout::new(
                tcp_connector,
                sleep_impl
                    .clone()
                    .expect("a sleep impl must be provided in order to have a connect timeout"),
                duration,
            ),
            None => timeout_middleware::ConnectTimeout::no_timeout(tcp_connector),
        };
        let base = client_builder.build(connector);
        let read_timeout = match read_timeout {
            Some(duration) => timeout_middleware::HttpReadTimeout::new(
                base,
                sleep_impl.expect("a sleep impl must be provided in order to have a read timeout"),
                duration,
            ),
            None => timeout_middleware::HttpReadTimeout::no_timeout(base),
        };
        HyperConnector {
            adapter: Box::new(Adapter {
                client: read_timeout,
            }),
        }
    }

    /// Set the async sleep implementation used for timeouts
    ///
    /// Calling this is only necessary for testing or to use something other than
    /// [`default_async_sleep`].
    pub fn sleep_impl(mut self, sleep_impl: impl AsyncSleep + 'static) -> Self {
        self.sleep_impl = Some(sleep_impl.into_shared());
        self
    }

    /// Set the async sleep implementation used for timeouts
    ///
    /// Calling this is only necessary for testing or to use something other than
    /// [`default_async_sleep`].
    pub fn set_sleep_impl(&mut self, sleep_impl: Option<SharedAsyncSleep>) -> &mut Self {
        self.sleep_impl = sleep_impl;
        self
    }

    /// Configure the HTTP settings for the `HyperAdapter`
    pub fn connector_settings(mut self, connector_settings: HttpConnectorSettings) -> Self {
        self.connector_settings = Some(connector_settings);
        self
    }

    /// Configure the HTTP settings for the `HyperAdapter`
    pub fn set_connector_settings(
        &mut self,
        connector_settings: Option<HttpConnectorSettings>,
    ) -> &mut Self {
        self.connector_settings = connector_settings;
        self
    }

    /// Override the Hyper client [`Builder`](hyper_util::client::legacy::Builder) used to construct this client.
    ///
    /// This enables changing settings like forcing HTTP2 and modifying other default client behavior.
    pub(crate) fn hyper_builder(
        mut self,
        hyper_builder: hyper_util::client::legacy::Builder,
    ) -> Self {
        self.set_hyper_builder(Some(hyper_builder));
        self
    }

    /// Override the Hyper client [`Builder`](hyper_util::client::legacy::Builder) used to construct this client.
    ///
    /// This enables changing settings like forcing HTTP2 and modifying other default client behavior.
    pub(crate) fn set_hyper_builder(
        &mut self,
        hyper_builder: Option<hyper_util::client::legacy::Builder>,
    ) -> &mut Self {
        self.client_builder = hyper_builder;
        self
    }
}

/// Adapter to use a Hyper 1.0-based Client as an `HttpConnector`
///
/// This adapter also enables TCP `CONNECT` and HTTP `READ` timeouts via [`HyperConnector::builder`].
struct Adapter<C> {
    client: timeout_middleware::HttpReadTimeout<
        hyper_util::client::legacy::Client<timeout_middleware::ConnectTimeout<C>, SdkBody>,
    >,
}

impl<C> fmt::Debug for Adapter<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Adapter")
            .field("client", &"** hyper client **")
            .finish()
    }
}

/// Extract a smithy connection from a hyper CaptureConnection
fn extract_smithy_connection(capture_conn: &CaptureConnection) -> Option<ConnectionMetadata> {
    let capture_conn = capture_conn.clone();
    if let Some(conn) = capture_conn.clone().connection_metadata().as_ref() {
        let mut extensions = Extensions::new();
        conn.get_extras(&mut extensions);
        let http_info = extensions.get::<HttpInfo>();
        let mut builder = ConnectionMetadata::builder()
            .proxied(conn.is_proxied())
            .poison_fn(move || match capture_conn.connection_metadata().as_ref() {
                Some(conn) => conn.poison(),
                None => tracing::trace!("no connection existed to poison"),
            });

        builder
            .set_local_addr(http_info.map(|info| info.local_addr()))
            .set_remote_addr(http_info.map(|info| info.remote_addr()));

        let smithy_connection = builder.build();

        Some(smithy_connection)
    } else {
        None
    }
}

impl<C> HttpConnector for Adapter<C>
where
    C: Clone + Send + Sync + 'static,
    C: tower::Service<Uri>,
    C::Response: Connection + Read + Write + Unpin + 'static,
    timeout_middleware::ConnectTimeout<C>: Connect,
    C::Future: Unpin + Send + 'static,
    C::Error: Into<BoxError>,
{
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let mut request = match request.try_into_http1x() {
            Ok(request) => request,
            Err(err) => {
                return HttpConnectorFuture::ready(Err(ConnectorError::user(err.into())));
            }
        };
        let capture_connection = capture_connection(&mut request);
        if let Some(capture_smithy_connection) =
            request.extensions().get::<CaptureSmithyConnection>()
        {
            capture_smithy_connection
                .set_connection_retriever(move || extract_smithy_connection(&capture_connection));
        }
        let mut client = self.client.clone();
        use tower::Service;
        let fut = client.call(request);
        HttpConnectorFuture::new(async move {
            let response = fut
                .await
                .map_err(downcast_error)?
                .map(SdkBody::from_body_1_x);
            match HttpResponse::try_from(response) {
                Ok(response) => Ok(response),
                Err(err) => Err(ConnectorError::other(err.into(), None)),
            }
        })
    }
}

/// Downcast errors coming out of hyper into an appropriate `ConnectorError`
fn downcast_error(err: BoxError) -> ConnectorError {
    // is a `TimedOutError` (from aws_smithy_async::timeout) in the chain? if it is, this is a timeout
    if find_source::<TimedOutError>(err.as_ref()).is_some() {
        return ConnectorError::timeout(err);
    }
    // is the top of chain error actually already a `ConnectorError`? return that directly
    let err = match err.downcast::<ConnectorError>() {
        Ok(connector_error) => return *connector_error,
        Err(box_error) => box_error,
    };
    // generally, the top of chain will probably be a hyper error. Go through a set of hyper specific
    // error classifications
    let err = match find_source::<hyper::Error>(err.as_ref()) {
        Some(hyper_error) => return to_connector_error(hyper_error)(err),
        None => err,
    };

    // otherwise, we have no idea!
    ConnectorError::other(err, None)
}

/// Convert a [`hyper::Error`] into a [`ConnectorError`]
fn to_connector_error(err: &hyper::Error) -> fn(BoxError) -> ConnectorError {
    if err.is_timeout() || find_source::<timeout_middleware::HttpTimeoutError>(err).is_some() {
        return ConnectorError::timeout;
    }
    if err.is_user() {
        return ConnectorError::user;
    }
    if err.is_closed() || err.is_canceled() || find_source::<std::io::Error>(err).is_some() {
        return ConnectorError::io;
    }
    // We sometimes receive this from S3: hyper::Error(IncompleteMessage)
    if err.is_incomplete_message() {
        return |err: BoxError| ConnectorError::other(err, Some(ErrorKind::TransientError));
    }

    if let Some(h2_err) = find_source::<h2::Error>(err) {
        if h2_err.is_go_away()
            || (h2_err.is_reset() && h2_err.reason() == Some(Reason::REFUSED_STREAM))
        {
            return ConnectorError::io;
        }
    }

    tracing::warn!(err = %DisplayErrorContext(&err), "unrecognized error from Hyper. If this error should be retried, please file an issue.");
    |err: BoxError| ConnectorError::other(err, None)
}

fn find_source<'a, E: Error + 'static>(err: &'a (dyn Error + 'static)) -> Option<&'a E> {
    let mut next = Some(err);
    while let Some(err) = next {
        if let Some(matching_err) = err.downcast_ref::<E>() {
            return Some(matching_err);
        }
        next = err.source();
    }
    None
}

// TODO(https://github.com/awslabs/aws-sdk-rust/issues/1090): CacheKey must also include ptr equality to any
// runtime components that are used—sleep_impl as a base (unless we prohibit overriding sleep impl)
// If we decide to put a DnsResolver in RuntimeComponents, then we'll need to handle that as well.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct CacheKey {
    connect_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
}

impl From<&HttpConnectorSettings> for CacheKey {
    fn from(value: &HttpConnectorSettings) -> Self {
        Self {
            connect_timeout: value.connect_timeout(),
            read_timeout: value.read_timeout(),
        }
    }
}

struct HyperClient<F> {
    connector_cache: RwLock<HashMap<CacheKey, SharedHttpConnector>>,
    client_builder: hyper_util::client::legacy::Builder,
    tcp_connector_fn: F,
}

impl<F> fmt::Debug for HyperClient<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HyperClient")
            .field("connector_cache", &self.connector_cache)
            .field("client_builder", &self.client_builder)
            .finish()
    }
}

impl<C, F> HttpClient for HyperClient<F>
where
    F: Fn() -> C + Send + Sync,
    C: Clone + Send + Sync + 'static,
    C: tower::Service<Uri>,
    C::Response: Connection + Read + Write + Send + Sync + Unpin + 'static,
    C::Future: Unpin + Send + 'static,
    C::Error: Into<BoxError>,
{
    fn http_connector(
        &self,
        settings: &HttpConnectorSettings,
        components: &RuntimeComponents,
    ) -> SharedHttpConnector {
        let key = CacheKey::from(settings);
        let mut connector = self.connector_cache.read().unwrap().get(&key).cloned();
        if connector.is_none() {
            let mut cache = self.connector_cache.write().unwrap();
            // Short-circuit if another thread already wrote a connector to the cache for this key
            if !cache.contains_key(&key) {
                let mut builder = HyperConnector::builder()
                    .hyper_builder(self.client_builder.clone())
                    .connector_settings(settings.clone());
                builder.set_sleep_impl(components.sleep_impl());

                let start = components.time_source().map(|ts| ts.now());
                let tcp_connector = (self.tcp_connector_fn)();
                let end = components.time_source().map(|ts| ts.now());
                if let (Some(start), Some(end)) = (start, end) {
                    if let Ok(elapsed) = end.duration_since(start) {
                        tracing::debug!("new TCP connector created in {:?}", elapsed);
                    }
                }
                let connector = SharedHttpConnector::new(builder.build(tcp_connector));
                cache.insert(key.clone(), connector);
            }
            connector = cache.get(&key).cloned();
        }

        connector.expect("cache populated above")
    }

    fn validate_base_client_config(
        &self,
        _: &RuntimeComponentsBuilder,
        _: &ConfigBag,
    ) -> Result<(), BoxError> {
        // Initialize the TCP connector at this point so that native certs load
        // at client initialization time instead of upon first request. We do it
        // here rather than at construction so that it won't run if this is not
        // the selected HTTP client for the base config (for example, if this was
        // the default HTTP client, and it was overridden by a later plugin).
        let _ = (self.tcp_connector_fn)();
        Ok(())
    }

    fn connector_metadata(&self) -> Option<ConnectorMetadata> {
        Some(ConnectorMetadata::new("hyper", Some(Cow::Borrowed("1.x"))))
    }
}

/// Builder for a hyper-backed [`HttpClient`] implementation.
///
/// This builder can be used to customize the underlying TCP connector used, as well as
/// hyper client configuration.
///
/// # Examples
///
/// Construct a Hyper client with the RusTLS TLS implementation.
/// This can be useful when you want to share a Hyper connector between multiple
/// generated Smithy clients.
#[derive(Clone, Default, Debug)]
pub struct HyperClientBuilder<Crypto = CryptoUnset> {
    client_builder: Option<hyper_util::client::legacy::Builder>,
    crypto_provider: Crypto,
}

impl HyperClientBuilder<CryptoProviderSelected> {
    /// Create a hyper client using RusTLS for TLS
    ///
    /// The trusted certificates will be loaded later when this becomes the selected
    /// HTTP client for a Smithy client.
    pub fn build_https(self) -> SharedHttpClient {
        let crypto = self.crypto_provider.crypto_provider;
        build_with_fn(self.client_builder, move || {
            cached_connectors::cached_https(crypto.clone())
        })
    }

    /// Create a hyper client using a custom DNS resolver
    pub fn build_with_resolver(
        self,
        resolver: impl ResolveDns + Clone + 'static,
    ) -> SharedHttpClient {
        build_with_fn(self.client_builder, move || {
            build_connector::https_with_resolver(
                self.crypto_provider.crypto_provider.clone(),
                resolver.clone(),
            )
        })
    }

    /// Create a hyper client using a proxy connector
    pub fn build_with_proxy<H, N>(self, https_proxy: H, no_proxy: Option<&[N]>) -> SharedHttpClient
    where
        H: AsRef<str> + Clone + Send + Sync + 'static,
        N: AsRef<str>,
    {
        let crypto = self.crypto_provider.crypto_provider;
        let no_proxy: Option<Vec<String>> =
            no_proxy.map(|n| n.iter().map(|s| s.as_ref().to_owned()).collect());
        build_with_fn(self.client_builder, move || {
            build_connector::https_with_proxy(
                cached_connectors::cached_https(crypto.clone()),
                https_proxy.as_ref(),
                no_proxy.clone(),
            )
        })
    }
}

impl HyperClientBuilder<CryptoUnset> {
    /// Creates a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn crypto_mode(self, provider: CryptoMode) -> HyperClientBuilder<CryptoProviderSelected> {
        HyperClientBuilder {
            client_builder: self.client_builder,
            crypto_provider: CryptoProviderSelected {
                crypto_provider: Inner::Standard(provider),
            },
        }
    }

    /// This interface will be broken in the future
    ///
    /// This exposes `CryptoProvider` from `rustls` directly and this API has no stability guarantee.
    #[cfg(crypto_unstable)]
    pub fn crypto_provider_unstable(
        self,
        provider: CryptoProvider,
    ) -> HyperClientBuilder<CryptoProviderSelected> {
        HyperClientBuilder {
            client_builder: self.client_builder,
            crypto_provider: CryptoProviderSelected {
                crypto_provider: Inner::Custom(provider),
            },
        }
    }
}

fn build_with_fn<C, F>(
    client_builder: Option<hyper_util::client::legacy::Builder>,
    tcp_connector_fn: F,
) -> SharedHttpClient
where
    F: Fn() -> C + Send + Sync + 'static,
    C: Clone + Send + Sync + 'static,
    C: tower::Service<Uri>,
    C::Response: Connection + Read + Write + Send + Sync + Unpin + 'static,
    C::Future: Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C: Connect,
{
    SharedHttpClient::new(HyperClient {
        connector_cache: RwLock::new(HashMap::new()),
        client_builder: client_builder
            .unwrap_or_else(|| hyper_util::client::legacy::Builder::new(TokioExecutor::new())),
        tcp_connector_fn,
    })
}

mod timeout_middleware {
    use std::error::Error;
    use std::fmt::Formatter;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use http::Uri;
    use pin_project_lite::pin_project;

    use aws_smithy_async::future::timeout::{TimedOutError, Timeout};
    use aws_smithy_async::rt::sleep::Sleep;
    use aws_smithy_async::rt::sleep::{AsyncSleep, SharedAsyncSleep};
    use aws_smithy_runtime_api::box_error::BoxError;

    #[derive(Debug)]
    pub(crate) struct HttpTimeoutError {
        kind: &'static str,
        duration: Duration,
    }

    impl std::fmt::Display for HttpTimeoutError {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "{} timeout occurred after {:?}",
                self.kind, self.duration
            )
        }
    }

    impl Error for HttpTimeoutError {
        // We implement the `source` function as returning a `TimedOutError` because when `downcast_error`
        // or `find_source` is called with an `HttpTimeoutError` (or another error wrapping an `HttpTimeoutError`)
        // this method will be checked to determine if it's a timeout-related error.
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&TimedOutError)
        }
    }

    /// Timeout wrapper that will timeout on the initial TCP connection
    ///
    /// # Stability
    /// This interface is unstable.
    #[derive(Clone, Debug)]
    pub(super) struct ConnectTimeout<I> {
        inner: I,
        timeout: Option<(SharedAsyncSleep, Duration)>,
    }

    impl<I> ConnectTimeout<I> {
        /// Create a new `ConnectTimeout` around `inner`.
        ///
        /// Typically, `I` will implement [`hyper_util::client::legacy::connect::Connect`].
        pub(crate) fn new(inner: I, sleep: SharedAsyncSleep, timeout: Duration) -> Self {
            Self {
                inner,
                timeout: Some((sleep, timeout)),
            }
        }

        pub(crate) fn no_timeout(inner: I) -> Self {
            Self {
                inner,
                timeout: None,
            }
        }
    }

    #[derive(Clone, Debug)]
    pub(crate) struct HttpReadTimeout<I> {
        inner: I,
        timeout: Option<(SharedAsyncSleep, Duration)>,
    }

    impl<I> HttpReadTimeout<I> {
        /// Create a new `HttpReadTimeout` around `inner`.
        ///
        /// Typically, `I` will implement [`tower::Service<http::Request<SdkBody>>`].
        pub(crate) fn new(inner: I, sleep: SharedAsyncSleep, timeout: Duration) -> Self {
            Self {
                inner,
                timeout: Some((sleep, timeout)),
            }
        }

        pub(crate) fn no_timeout(inner: I) -> Self {
            Self {
                inner,
                timeout: None,
            }
        }
    }

    pin_project! {
        /// Timeout future for Tower services
        ///
        /// Timeout future to handle timing out, mapping errors, and the possibility of not timing out
        /// without incurring an additional allocation for each timeout layer.
        #[project = MaybeTimeoutFutureProj]
        pub enum MaybeTimeoutFuture<F> {
            Timeout {
                #[pin]
                timeout: Timeout<F, Sleep>,
                error_type: &'static str,
                duration: Duration,
            },
            NoTimeout {
                #[pin]
                future: F
            }
        }
    }

    impl<F, T, E> Future for MaybeTimeoutFuture<F>
    where
        F: Future<Output = Result<T, E>>,
        E: Into<BoxError>,
    {
        type Output = Result<T, BoxError>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let (timeout_future, kind, &mut duration) = match self.project() {
                MaybeTimeoutFutureProj::NoTimeout { future } => {
                    return future.poll(cx).map_err(|err| err.into());
                }
                MaybeTimeoutFutureProj::Timeout {
                    timeout,
                    error_type,
                    duration,
                } => (timeout, error_type, duration),
            };
            match timeout_future.poll(cx) {
                Poll::Ready(Ok(response)) => Poll::Ready(response.map_err(|err| err.into())),
                Poll::Ready(Err(_timeout)) => {
                    Poll::Ready(Err(HttpTimeoutError { kind, duration }.into()))
                }
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl<I> tower::Service<Uri> for ConnectTimeout<I>
    where
        I: tower::Service<Uri>,
        I::Error: Into<BoxError>,
    {
        type Response = I::Response;
        type Error = BoxError;
        type Future = MaybeTimeoutFuture<I::Future>;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.inner.poll_ready(cx).map_err(|err| err.into())
        }

        fn call(&mut self, req: Uri) -> Self::Future {
            match &self.timeout {
                Some((sleep, duration)) => {
                    let sleep = sleep.sleep(*duration);
                    MaybeTimeoutFuture::Timeout {
                        timeout: Timeout::new(self.inner.call(req), sleep),
                        error_type: "HTTP connect",
                        duration: *duration,
                    }
                }
                None => MaybeTimeoutFuture::NoTimeout {
                    future: self.inner.call(req),
                },
            }
        }
    }

    impl<I, B> tower::Service<http::Request<B>> for HttpReadTimeout<I>
    where
        I: tower::Service<http::Request<B>>,
        I::Error: Send + Sync + Error + 'static,
    {
        type Response = I::Response;
        type Error = BoxError;
        type Future = MaybeTimeoutFuture<I::Future>;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.inner.poll_ready(cx).map_err(|err| err.into())
        }

        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            match &self.timeout {
                Some((sleep, duration)) => {
                    let sleep = sleep.sleep(*duration);
                    MaybeTimeoutFuture::Timeout {
                        timeout: Timeout::new(self.inner.call(req), sleep),
                        error_type: "HTTP read",
                        duration: *duration,
                    }
                }
                None => MaybeTimeoutFuture::NoTimeout {
                    future: self.inner.call(req),
                },
            }
        }
    }

    #[cfg(test)]
    pub(crate) mod test {
        use std::time::Duration;

        use hyper::rt::ReadBufCursor;
        use hyper_util::client::legacy::connect::Connected;
        use hyper_util::rt::TokioIo;
        use tokio::net::TcpStream;

        use aws_smithy_async::assert_elapsed;
        use aws_smithy_async::future::never::Never;
        use aws_smithy_async::rt::sleep::{SharedAsyncSleep, TokioSleep};
        use aws_smithy_types::error::display::DisplayErrorContext;

        use super::super::*;

        #[allow(unused)]
        fn connect_timeout_is_correct<T: Send + Sync + Clone + 'static>() {
            is_send_sync::<super::ConnectTimeout<T>>();
        }

        #[allow(unused)]
        fn is_send_sync<T: Send + Sync>() {}

        /// A service that will never return whatever it is you want
        ///
        /// Returned futures will return Pending forever
        #[non_exhaustive]
        #[derive(Clone, Default, Debug)]
        pub(crate) struct NeverConnects;
        impl tower::Service<Uri> for NeverConnects {
            type Response = TokioIo<TcpStream>;
            type Error = ConnectorError;
            type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, _uri: Uri) -> Self::Future {
                Box::pin(async move {
                    Never::new().await;
                    unreachable!()
                })
            }
        }

        /// A service that will connect but never send any data
        #[derive(Clone, Debug, Default)]
        struct NeverReplies;
        impl tower::Service<Uri> for NeverReplies {
            type Response = EmptyStream;
            type Error = BoxError;
            type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, _req: Uri) -> Self::Future {
                std::future::ready(Ok(EmptyStream))
            }
        }

        /// A stream that will never return or accept any data
        #[non_exhaustive]
        #[derive(Debug, Default)]
        struct EmptyStream;
        impl Read for EmptyStream {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: ReadBufCursor<'_>,
            ) -> Poll<Result<(), std::io::Error>> {
                Poll::Pending
            }
        }
        impl Write for EmptyStream {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &[u8],
            ) -> Poll<Result<usize, std::io::Error>> {
                Poll::Pending
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Result<(), std::io::Error>> {
                Poll::Pending
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Result<(), std::io::Error>> {
                Poll::Pending
            }
        }
        impl Connection for EmptyStream {
            fn connected(&self) -> Connected {
                Connected::new()
            }
        }

        #[tokio::test]
        async fn http_connect_timeout_works() {
            let tcp_connector = NeverConnects::default();
            let connector_settings = HttpConnectorSettings::builder()
                .connect_timeout(Duration::from_secs(1))
                .build();
            let hyper = HyperConnector::builder()
                .connector_settings(connector_settings)
                .sleep_impl(SharedAsyncSleep::new(TokioSleep::new()))
                .build(tcp_connector)
                .adapter;
            let now = tokio::time::Instant::now();
            tokio::time::pause();
            let resp = hyper
                .call(HttpRequest::get("https://static-uri.com").unwrap())
                .await
                .unwrap_err();
            assert!(
                resp.is_timeout(),
                "expected resp.is_timeout() to be true but it was false, resp == {:?}",
                resp
            );
            let message = DisplayErrorContext(&resp).to_string();
            let expected =
                "timeout: client error (Connect): HTTP connect timeout occurred after 1s";
            assert!(
                message.contains(expected),
                "expected '{message}' to contain '{expected}'"
            );
            assert_elapsed!(now, Duration::from_secs(1));
        }

        #[tokio::test]
        async fn http_read_timeout_works() {
            let tcp_connector = NeverReplies;
            let connector_settings = HttpConnectorSettings::builder()
                .connect_timeout(Duration::from_secs(1))
                .read_timeout(Duration::from_secs(2))
                .build();
            let hyper = HyperConnector::builder()
                .connector_settings(connector_settings)
                .sleep_impl(SharedAsyncSleep::new(TokioSleep::new()))
                .build(tcp_connector)
                .adapter;
            let now = tokio::time::Instant::now();
            tokio::time::pause();
            let err = hyper
                .call(HttpRequest::get("https://fake-uri.com").unwrap())
                .await
                .unwrap_err();
            assert!(
                err.is_timeout(),
                "expected err.is_timeout() to be true but it was false, err == {err:?}",
            );
            let message = format!("{}", DisplayErrorContext(&err));
            let expected = "timeout: HTTP read timeout occurred after 2s";
            assert!(
                message.contains(expected),
                "expected '{message}' to contain '{expected}'"
            );
            assert_elapsed!(now, Duration::from_secs(2));
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::{Error, ErrorKind};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use http::Uri;
    use hyper::rt::ReadBufCursor;
    use hyper_util::client::legacy::connect::Connected;

    use aws_smithy_async::time::SystemTimeSource;
    use aws_smithy_runtime_api::client::runtime_components::RuntimeComponentsBuilder;

    use crate::hyper_1_0::timeout_middleware::test::NeverConnects;

    use super::*;

    #[tokio::test]
    async fn connector_selection() {
        // Create a client that increments a count every time it creates a new HyperConnector
        let creation_count = Arc::new(AtomicU32::new(0));
        let http_client = build_with_fn(None, {
            let count = creation_count.clone();
            move || {
                count.fetch_add(1, Ordering::Relaxed);
                NeverConnects
            }
        });

        // This configuration should result in 4 separate connectors with different timeout settings
        let settings = [
            HttpConnectorSettings::builder()
                .connect_timeout(Duration::from_secs(3))
                .build(),
            HttpConnectorSettings::builder()
                .read_timeout(Duration::from_secs(3))
                .build(),
            HttpConnectorSettings::builder()
                .connect_timeout(Duration::from_secs(3))
                .read_timeout(Duration::from_secs(3))
                .build(),
            HttpConnectorSettings::builder()
                .connect_timeout(Duration::from_secs(5))
                .read_timeout(Duration::from_secs(3))
                .build(),
        ];

        // Kick off thousands of parallel tasks that will try to create a connector
        let components = RuntimeComponentsBuilder::for_tests()
            .with_time_source(Some(SystemTimeSource::new()))
            .build()
            .unwrap();
        let mut handles = Vec::new();
        for setting in &settings {
            for _ in 0..1000 {
                let client = http_client.clone();
                handles.push(tokio::spawn({
                    let setting = setting.clone();
                    let components = components.clone();
                    async move {
                        let _ = client.http_connector(&setting, &components);
                    }
                }));
            }
        }
        for handle in handles {
            handle.await.unwrap();
        }

        // Verify only 4 connectors were created amidst the chaos
        assert_eq!(4, creation_count.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn hyper_io_error() {
        let connector = TestConnection {
            inner: HangupStream,
        };
        let adapter = HyperConnector::builder().build(connector).adapter;
        let err = adapter
            .call(HttpRequest::get("https://socket-hangup.com").unwrap())
            .await
            .expect_err("socket hangup");
        assert!(err.is_io(), "unexpected error type: {:?}", err);
    }

    // ---- machinery to make a Hyper connector that responds with an IO Error
    #[derive(Clone)]
    struct HangupStream;

    impl Connection for HangupStream {
        fn connected(&self) -> Connected {
            Connected::new()
        }
    }

    impl Read for HangupStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: ReadBufCursor<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Err(Error::new(
                ErrorKind::ConnectionReset,
                "connection reset",
            )))
        }
    }

    impl Write for HangupStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<Result<usize, Error>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
            Poll::Pending
        }
    }

    #[derive(Clone)]
    struct TestConnection<T> {
        inner: T,
    }

    impl<T> tower::Service<Uri> for TestConnection<T>
    where
        T: Clone + Connection,
    {
        type Response = T;
        type Error = BoxError;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Uri) -> Self::Future {
            std::future::ready(Ok(self.inner.clone()))
        }
    }
}
