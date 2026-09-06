// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

use iggy::prelude::{
    AutoLogin as RustAutoLogin, Credentials as RustCredentials,
    HttpClientConfig as RustHttpClientConfig, HttpClientConfigBuilder,
    TcpClientConfig as RustTcpClientConfig, TcpClientConfigBuilder,
    TcpClientReconnectionConfig as RustTcpClientReconnectionConfig,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDelta;
use pyo3_stub_gen::derive::{gen_stub_pyclass, gen_stub_pymethods};
use pyo3_stub_gen::impl_stub_type;
use secrecy::SecretString;
use std::sync::Arc;

use crate::duration::{
    duration_repr, iggy_duration_to_py_delta, py_delta_to_iggy_duration, reject_zero,
};

/// The credentials replayed by the client every time it (re)connects.
///
/// `IggyClient` only recovers a lost session when it has credentials to replay,
/// so a long-running consumer should pass one of the enabled variants.
#[gen_stub_pyclass]
#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct AutoLogin {
    pub(crate) inner: RustAutoLogin,
}

#[gen_stub_pymethods]
#[pymethods]
impl AutoLogin {
    /// No automatic login. `login_user()` must be called by hand after every connect.
    #[staticmethod]
    fn disabled() -> Self {
        Self {
            inner: RustAutoLogin::Disabled,
        }
    }

    /// Log in with the given username and password on every connect.
    #[staticmethod]
    fn username_password(username: String, password: String) -> Self {
        Self {
            inner: RustAutoLogin::Enabled(RustCredentials::UsernamePassword(
                username,
                SecretString::from(password),
            )),
        }
    }

    /// Log in with the given personal access token on every connect.
    #[staticmethod]
    fn personal_access_token(token: String) -> Self {
        Self {
            inner: RustAutoLogin::Enabled(RustCredentials::PersonalAccessToken(
                SecretString::from(token),
            )),
        }
    }

    /// Whether automatic login is enabled.
    #[getter]
    fn enabled(&self) -> bool {
        matches!(self.inner, RustAutoLogin::Enabled(_))
    }

    /// The username to log in with, or `None` for the disabled and token variants.
    #[gen_stub(override_return_type(type_repr = "builtins.str | None"))]
    #[getter]
    fn username(&self) -> Option<String> {
        match &self.inner {
            RustAutoLogin::Enabled(RustCredentials::UsernamePassword(username, _)) => {
                Some(username.clone())
            }
            _ => None,
        }
    }

    fn __repr__(&self) -> String {
        match &self.inner {
            RustAutoLogin::Disabled => "AutoLogin.disabled()".to_owned(),
            RustAutoLogin::Enabled(RustCredentials::UsernamePassword(username, _)) => {
                format!("AutoLogin.username_password({username:?}, ...)")
            }
            RustAutoLogin::Enabled(RustCredentials::PersonalAccessToken(_)) => {
                "AutoLogin.personal_access_token(...)".to_owned()
            }
        }
    }
}

/// How the TCP client reconnects after the connection to the server is lost.
#[gen_stub_pyclass]
#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct TcpReconnectionConfig {
    pub(crate) inner: RustTcpClientReconnectionConfig,
}

#[gen_stub_pymethods]
#[pymethods]
impl TcpReconnectionConfig {
    /// Constructs a reconnection policy.
    ///
    /// Args:
    ///     enabled: Whether to reconnect at all. Defaults to enabled.
    ///     max_retries: Passes over the known endpoints after the first, or
    ///         `None` for unlimited; `0` still makes that first pass. One pass
    ///         tries the endpoint the client is on, the address it was
    ///         configured with, and every node the roster named, so this counts
    ///         passes rather than dials. Defaults
    ///         to unlimited, which means a call awaited while the server is
    ///         down never returns: `connect()`, `send_messages()` and
    ///         `poll_messages()` all wait inside the retry loop. Set a finite
    ///         number for request/reply style usage, so a call fails instead.
    ///     interval: Delay between passes. Defaults to 1 second. The first pass
    ///         runs at once when more than one endpoint is known.
    ///     reestablish_after: Cooldown before redialing the endpoint of the last
    ///         successful connection, measured from when it was established, so
    ///         a session that outlived the interval is redialed at once. Owed to
    ///         that endpoint alone. Defaults to 5 seconds.
    ///
    /// Raises:
    ///     ValueError: If a duration is negative, if `max_retries` is outside the
    ///         range of an unsigned 32-bit integer, or if `interval` is zero.
    #[new]
    #[pyo3(signature = (*, enabled=None, max_retries=None, interval=None, reestablish_after=None))]
    fn new(
        #[gen_stub(override_type(type_repr = "builtins.bool | None"))] enabled: Option<bool>,
        #[gen_stub(override_type(type_repr = "builtins.int | None"))] max_retries: Option<i64>,
        #[gen_stub(override_type(type_repr = "datetime.timedelta | None", imports=("datetime")))]
        interval: Option<Py<PyDelta>>,
        #[gen_stub(override_type(type_repr = "datetime.timedelta | None", imports=("datetime")))]
        reestablish_after: Option<Py<PyDelta>>,
    ) -> PyResult<Self> {
        let defaults = RustTcpClientReconnectionConfig::default();
        let enabled = enabled.unwrap_or(defaults.enabled);
        let max_retries = max_retries
            .map(|max_retries| u32_arg(max_retries, "max_retries"))
            .transpose()?;
        let interval = interval
            .as_ref()
            .map(py_delta_to_iggy_duration)
            .transpose()?
            .map(|interval| reject_zero(interval, "interval"))
            .transpose()?
            .unwrap_or(defaults.interval);
        Ok(Self {
            inner: RustTcpClientReconnectionConfig {
                enabled,
                max_retries,
                interval,
                reestablish_after: reestablish_after
                    .as_ref()
                    .map(py_delta_to_iggy_duration)
                    .transpose()?
                    .unwrap_or(defaults.reestablish_after),
            },
        })
    }

    #[getter]
    fn enabled(&self) -> bool {
        self.inner.enabled
    }

    #[gen_stub(override_return_type(type_repr = "builtins.int | None"))]
    #[getter]
    fn max_retries(&self) -> Option<u32> {
        self.inner.max_retries
    }

    #[gen_stub(override_return_type(type_repr = "datetime.timedelta", imports=("datetime")))]
    #[getter]
    fn interval<'a>(&self, py: Python<'a>) -> PyResult<Bound<'a, PyDelta>> {
        iggy_duration_to_py_delta(py, self.inner.interval.get())
    }

    #[gen_stub(override_return_type(type_repr = "datetime.timedelta", imports=("datetime")))]
    #[getter]
    fn reestablish_after<'a>(&self, py: Python<'a>) -> PyResult<Bound<'a, PyDelta>> {
        iggy_duration_to_py_delta(py, self.inner.reestablish_after)
    }

    fn __repr__(&self) -> String {
        let max_retries = match self.inner.max_retries {
            Some(max_retries) => max_retries.to_string(),
            None => "None".to_owned(),
        };
        format!(
            "TcpReconnectionConfig(enabled={}, max_retries={max_retries}, interval={}, reestablish_after={})",
            python_bool(self.inner.enabled),
            duration_repr(self.inner.interval.get()),
            duration_repr(self.inner.reestablish_after),
        )
    }
}

/// Configuration for the TCP transport, accepted by `IggyClient(...)`.
///
/// Every field is keyword-only and optional.
#[gen_stub_pyclass]
#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct TcpConfig {
    inner: Arc<RustTcpClientConfig>,
}

impl TcpConfig {
    /// The configuration in the shape `TcpClient::create` expects.
    pub(crate) fn client_config(&self) -> Arc<RustTcpClientConfig> {
        self.inner.clone()
    }
}

#[gen_stub_pymethods]
#[pymethods]
impl TcpConfig {
    /// Constructs a TCP configuration.
    ///
    /// Args:
    ///     server_address: `host:port` of the Iggy server. Defaults to `127.0.0.1:8090`.
    ///     auto_login: Credentials replayed on every connect. Defaults to `AutoLogin.disabled()`.
    ///     reconnection: Reconnection policy. Defaults to `TcpReconnectionConfig()`.
    ///     heartbeat_interval: Interval of heartbeats sent by the client. Defaults to 5 seconds.
    ///     tls_enabled: Whether to connect over TLS. Defaults to disabled.
    ///     tls_domain: Domain to validate the certificate against. Empty means it is
    ///         taken from `server_address`.
    ///     tls_ca_file: Path to the CA file for TLS. Read only when `tls_enabled`
    ///         and `tls_validate_certificate` are both on; with either one off it
    ///         is kept but never consulted, so pairing it with
    ///         `tls_validate_certificate=False` pins nothing.
    ///     tls_validate_certificate: Whether to validate the server certificate.
    ///         Defaults to validating. Disabling this accepts any certificate the
    ///         server presents, including self-signed and mismatched ones, and
    ///         takes precedence over `tls_ca_file`; intended for local development
    ///         only.
    ///     nodelay: Disable the Nagle algorithm for the TCP socket. Defaults to
    ///         leaving it on.
    ///
    /// Raises:
    ///     ValueError: If `server_address` is not a valid `host:port` pair, if a
    ///         duration is negative, or if `heartbeat_interval` is zero.
    #[new]
    #[pyo3(signature = (
        *,
        server_address=None,
        auto_login=None,
        reconnection=None,
        heartbeat_interval=None,
        tls_enabled=None,
        tls_domain=None,
        tls_ca_file=None,
        tls_validate_certificate=None,
        nodelay=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        #[gen_stub(override_type(type_repr = "builtins.str | None"))] server_address: Option<
            String,
        >,
        #[gen_stub(override_type(type_repr = "AutoLogin | None"))] auto_login: Option<AutoLogin>,
        #[gen_stub(override_type(type_repr = "TcpReconnectionConfig | None"))] reconnection: Option<
            TcpReconnectionConfig,
        >,
        #[gen_stub(override_type(type_repr = "datetime.timedelta | None", imports=("datetime")))]
        heartbeat_interval: Option<Py<PyDelta>>,
        #[gen_stub(override_type(type_repr = "builtins.bool | None"))] tls_enabled: Option<bool>,
        #[gen_stub(override_type(type_repr = "builtins.str | None"))] tls_domain: Option<String>,
        #[gen_stub(override_type(type_repr = "builtins.str | None"))] tls_ca_file: Option<String>,
        #[gen_stub(override_type(type_repr = "builtins.bool | None"))]
        tls_validate_certificate: Option<bool>,
        #[gen_stub(override_type(type_repr = "builtins.bool | None"))] nodelay: Option<bool>,
    ) -> PyResult<Self> {
        // The builder starts from `TcpClientConfig::default()`, and its `build()`
        // trims and validates the address whether or not one was set here.
        let mut builder = TcpClientConfigBuilder::new();
        if let Some(server_address) = server_address {
            builder = builder.with_server_address(server_address);
        }
        let mut inner = builder
            .build()
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        if let Some(auto_login) = auto_login {
            inner.auto_login = auto_login.inner;
        }
        if let Some(reconnection) = reconnection {
            inner.reconnection = reconnection.inner;
        }
        if let Some(heartbeat_interval) = heartbeat_interval {
            inner.heartbeat_interval = reject_zero(
                py_delta_to_iggy_duration(&heartbeat_interval)?,
                "heartbeat_interval",
            )?;
        }
        if let Some(tls_enabled) = tls_enabled {
            inner.tls_enabled = tls_enabled;
        }
        if let Some(tls_domain) = tls_domain {
            inner.tls_domain = tls_domain;
        }
        if tls_ca_file.is_some() {
            inner.tls_ca_file = tls_ca_file;
        }
        if let Some(tls_validate_certificate) = tls_validate_certificate {
            inner.tls_validate_certificate = tls_validate_certificate;
        }
        if let Some(nodelay) = nodelay {
            inner.nodelay = nodelay;
        }

        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    #[getter]
    fn server_address(&self) -> String {
        self.inner.server_address.clone()
    }

    #[getter]
    fn auto_login(&self) -> AutoLogin {
        AutoLogin {
            inner: self.inner.auto_login.clone(),
        }
    }

    #[getter]
    fn reconnection(&self) -> TcpReconnectionConfig {
        TcpReconnectionConfig {
            inner: self.inner.reconnection.clone(),
        }
    }

    #[gen_stub(override_return_type(type_repr = "datetime.timedelta", imports=("datetime")))]
    #[getter]
    fn heartbeat_interval<'a>(&self, py: Python<'a>) -> PyResult<Bound<'a, PyDelta>> {
        iggy_duration_to_py_delta(py, self.inner.heartbeat_interval.get())
    }

    #[getter]
    fn tls_enabled(&self) -> bool {
        self.inner.tls_enabled
    }

    #[getter]
    fn tls_domain(&self) -> String {
        self.inner.tls_domain.clone()
    }

    #[gen_stub(override_return_type(type_repr = "builtins.str | None"))]
    #[getter]
    fn tls_ca_file(&self) -> Option<String> {
        self.inner.tls_ca_file.clone()
    }

    #[getter]
    fn tls_validate_certificate(&self) -> bool {
        self.inner.tls_validate_certificate
    }

    #[getter]
    fn nodelay(&self) -> bool {
        self.inner.nodelay
    }

    fn __repr__(&self) -> String {
        let tls_ca_file = match &self.inner.tls_ca_file {
            Some(tls_ca_file) => format!("{tls_ca_file:?}"),
            None => "None".to_owned(),
        };
        format!(
            "TcpConfig(server_address={:?}, auto_login={}, reconnection={}, heartbeat_interval={}, tls_enabled={}, tls_domain={:?}, tls_ca_file={tls_ca_file}, tls_validate_certificate={}, nodelay={})",
            self.inner.server_address,
            self.auto_login().__repr__(),
            self.reconnection().__repr__(),
            duration_repr(self.inner.heartbeat_interval.get()),
            python_bool(self.inner.tls_enabled),
            self.inner.tls_domain,
            python_bool(self.inner.tls_validate_certificate),
            python_bool(self.inner.nodelay),
        )
    }
}

/// Configuration for the HTTP transport, accepted by `IggyClient(...)`.
///
/// Every field is keyword-only and optional.
///
/// HTTP is single-consumer only. The consumer kind is not carried on the HTTP
/// wire, so a `Consumer.Group(...)` poll does not fail - it is served as an
/// ordinary consumer named after the group, with no membership, no partition
/// assignment, and no rebalancing behind it. Pass `Consumer.Single(...)`
/// explicitly.
#[gen_stub_pyclass]
#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct HttpConfig {
    inner: Arc<RustHttpClientConfig>,
}

impl HttpConfig {
    /// The configuration in the shape `HttpClient::create` expects.
    pub(crate) fn client_config(&self) -> Arc<RustHttpClientConfig> {
        self.inner.clone()
    }
}

#[gen_stub_pymethods]
#[pymethods]
impl HttpConfig {
    /// Constructs an HTTP configuration.
    ///
    /// Args:
    ///     api_url: Base URL of the Iggy HTTP API, as `scheme://host[:port]`
    ///         only - no path, query, fragment, or credentials. Defaults to
    ///         `http://127.0.0.1:3000`.
    ///     retries: Number of retries to perform on transient errors, each one
    ///         replaying the full request (including its body) via automatic
    ///         middleware. Defaults to 3. Delivery is therefore at-least-once:
    ///         if the original request actually committed but its response
    ///         was lost (e.g. to a timeout), a retried call applies the same
    ///         operation again. Set to 0 to disable automatic replay and match
    ///         the other transports, which surface the failure instead of
    ///         silently resending.
    ///     jwt: JWT token for A2A (Agent-to-Agent) authentication. Defaults to
    ///         `None`. Rejected if empty or whitespace-only: accepting it
    ///         would make `has_jwt` report `True` while every call still
    ///         fails `Unauthenticated`.
    ///     heartbeat_interval: Interval between the client's liveness probes
    ///         (a bare `GET /ping`). Defaults to 5 seconds. Unlike TCP/QUIC,
    ///         HTTP has no persistent connection or session for this to keep
    ///         alive; it only proves the server is reachable.
    ///
    /// Raises:
    ///     ValueError: If `api_url` is not a valid URL, if `retries` is outside
    ///         the range of an unsigned 32-bit integer, if `jwt` is empty or
    ///         whitespace-only, if a duration is negative, or if
    ///         `heartbeat_interval` is zero.
    ///     OverflowError: If `retries` does not fit a signed 64-bit integer,
    ///         raised by the underlying conversion before this constructor runs.
    #[new]
    #[pyo3(signature = (*, api_url=None, retries=None, jwt=None, heartbeat_interval=None))]
    fn new(
        #[gen_stub(override_type(type_repr = "builtins.str | None"))] api_url: Option<String>,
        #[gen_stub(override_type(type_repr = "builtins.int | None"))] retries: Option<i64>,
        #[gen_stub(override_type(type_repr = "builtins.str | None"))] jwt: Option<String>,
        #[gen_stub(override_type(type_repr = "datetime.timedelta | None", imports=("datetime")))]
        heartbeat_interval: Option<Py<PyDelta>>,
    ) -> PyResult<Self> {
        // The builder starts from `HttpClientConfig::default()`, and its `build()`
        // trims and validates the API URL whether or not one was set here.
        let mut builder = HttpClientConfigBuilder::new();
        if let Some(api_url) = api_url {
            builder = builder.with_api_url(api_url);
        }
        if let Some(retries) = retries {
            builder = builder.with_retries(u32_arg(retries, "retries")?);
        }
        if let Some(jwt) = jwt {
            if jwt.trim().is_empty() {
                return Err(PyValueError::new_err(
                    "'jwt' must not be empty or whitespace-only",
                ));
            }
            builder = builder.with_jwt(jwt);
        }
        if let Some(heartbeat_interval) = heartbeat_interval {
            let heartbeat_interval = reject_zero(
                py_delta_to_iggy_duration(&heartbeat_interval)?,
                "heartbeat_interval",
            )?;
            builder = builder.with_heartbeat_interval(heartbeat_interval);
        }
        let inner = builder
            .build()
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    #[getter]
    fn api_url(&self) -> String {
        self.inner.api_url.clone()
    }

    #[getter]
    fn retries(&self) -> u32 {
        self.inner.retries
    }

    /// Whether a JWT is configured, without exposing the token itself.
    #[getter]
    fn has_jwt(&self) -> bool {
        self.inner.jwt.is_some()
    }

    #[gen_stub(override_return_type(type_repr = "datetime.timedelta", imports=("datetime")))]
    #[getter]
    fn heartbeat_interval<'a>(&self, py: Python<'a>) -> PyResult<Bound<'a, PyDelta>> {
        iggy_duration_to_py_delta(py, self.inner.heartbeat_interval.get())
    }

    fn __repr__(&self) -> String {
        let jwt = if self.inner.jwt.is_some() {
            "..."
        } else {
            "None"
        };
        format!(
            "HttpConfig(api_url={:?}, retries={}, jwt={jwt}, heartbeat_interval={})",
            self.inner.api_url,
            self.inner.retries,
            duration_repr(self.inner.heartbeat_interval.get()),
        )
    }
}

fn python_bool(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}

/// Converts a Python int to the unsigned 32-bit integer `max_retries`/`retries`
/// expect, naming the parameter in the error so a caller can tell which
/// argument was out of range. A value too large even for `i64` still raises
/// pyo3's own unnamed `OverflowError` before this ever runs.
fn u32_arg(value: i64, parameter: &str) -> PyResult<u32> {
    u32::try_from(value).map_err(|_| {
        PyValueError::new_err(format!("'{parameter}' must be between 0 and {}", u32::MAX))
    })
}

/// What `IggyClient(...)` accepts: a bare `host:port`, a full `TcpConfig`, or an
/// `HttpConfig` for the HTTP transport.
#[derive(FromPyObject)]
pub enum PyClientConfig {
    #[pyo3(transparent)]
    Tcp(TcpConfig),
    #[pyo3(transparent)]
    Http(HttpConfig),
    #[pyo3(transparent, annotation = "str")]
    ServerAddress(String),
}
impl_stub_type!(PyClientConfig = TcpConfig | HttpConfig | String);
