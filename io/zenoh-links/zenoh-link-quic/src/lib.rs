//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//

//! ⚠️ WARNING ⚠️
//!
//! This crate is intended for Zenoh's internal use.
//!
//! [Click here for Zenoh's documentation](../zenoh/index.html)
use async_std::net::ToSocketAddrs;
use async_trait::async_trait;
use config::{
    TLS_ROOT_CA_CERTIFICATE_FILE, TLS_SERVER_CERTIFICATE_FILE, TLS_SERVER_NAME_VERIFICATION,
    TLS_SERVER_PRIVATE_KEY_FILE,
};
use std::net::SocketAddr;
use zenoh_config::Config;
use zenoh_core::zconfigurable;
use zenoh_link_commons::{ConfigurationInspector, LocatorInspector};
use zenoh_protocol::core::{
    endpoint::{Address, Parameters},
    Locator,
};
use zenoh_result::{bail, ZResult};

mod unicast;
mod verify;
pub use unicast::*;

// Default ALPN protocol
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

// Default MTU (QUIC PDU) in bytes.
// NOTE: Since QUIC is a byte-stream oriented transport, theoretically it has
//       no limit regarding the MTU. However, given the batching strategy
//       adopted in Zenoh and the usage of 16 bits in Zenoh to encode the
//       payload length in byte-streamed, the QUIC MTU is constrained to
//       2^16 - 1 bytes (i.e., 65535).
const QUIC_MAX_MTU: u16 = u16::MAX;
pub const QUIC_LOCATOR_PREFIX: &str = "quic";

#[derive(Default, Clone, Copy, Debug)]
pub struct QuicLocatorInspector;

#[async_trait]
impl LocatorInspector for QuicLocatorInspector {
    fn protocol(&self) -> &str {
        QUIC_LOCATOR_PREFIX
    }

    async fn is_multicast(&self, _locator: &Locator) -> ZResult<bool> {
        Ok(false)
    }
}

#[derive(Default, Clone, Copy, Debug)]
pub struct QuicConfigurator;

#[async_trait]
impl ConfigurationInspector<Config> for QuicConfigurator {
    async fn inspect_config(&self, config: &Config) -> ZResult<String> {
        let mut ps: Vec<(&str, &str)> = vec![];

        let c = config.transport().link().tls();
        if let Some(tls_ca_certificate) = c.root_ca_certificate() {
            ps.push((TLS_ROOT_CA_CERTIFICATE_FILE, tls_ca_certificate));
        }
        if let Some(tls_server_private_key) = c.server_private_key() {
            ps.push((TLS_SERVER_PRIVATE_KEY_FILE, tls_server_private_key));
        }
        if let Some(tls_server_certificate) = c.server_certificate() {
            ps.push((TLS_SERVER_CERTIFICATE_FILE, tls_server_certificate));
        }
        if let Some(server_name_verification) = c.server_name_verification() {
            match server_name_verification {
                true => ps.push((TLS_SERVER_NAME_VERIFICATION, "true")),
                false => ps.push((TLS_SERVER_NAME_VERIFICATION, "false")),
            };
        }

        let mut s = String::new();
        Parameters::extend(ps.drain(..), &mut s);

        Ok(s)
    }
}

zconfigurable! {
    // Default MTU (QUIC PDU) in bytes.
    static ref QUIC_DEFAULT_MTU: u16 = QUIC_MAX_MTU;
    // The LINGER option causes the shutdown() call to block until (1) all application data is delivered
    // to the remote end or (2) a timeout expires. The timeout is expressed in seconds.
    // More info on the LINGER option and its dynamics can be found at:
    // https://blog.netherlabs.nl/articles/2009/01/18/the-ultimate-so_linger-page-or-why-is-my-tcp-not-reliable
    static ref QUIC_LINGER_TIMEOUT: i32 = 10;
    // Amount of time in microseconds to throttle the accept loop upon an error.
    // Default set to 100 ms.
    static ref QUIC_ACCEPT_THROTTLE_TIME: u64 = 100_000;
}

pub mod config {
    pub const TLS_ROOT_CA_CERTIFICATE_FILE: &str = "root_ca_certificate_file";
    pub const TLS_ROOT_CA_CERTIFICATE_RAW: &str = "root_ca_certificate_raw";

    pub const TLS_SERVER_PRIVATE_KEY_FILE: &str = "server_private_key_file";
    pub const TLS_SERVER_PRIVATE_KEY_RAW: &str = "server_private_key_raw";

    pub const TLS_SERVER_CERTIFICATE_FILE: &str = "tls_server_certificate_file";
    pub const TLS_SERVER_CERTIFICATE_RAW: &str = "tls_server_certificate_raw";

    pub const TLS_SERVER_NAME_VERIFICATION: &str = "server_name_verification";
    pub const TLS_SERVER_NAME_VERIFICATION_DEFAULT: &str = "true";
}

async fn get_quic_addr(address: &Address<'_>) -> ZResult<SocketAddr> {
    match address.as_str().to_socket_addrs().await?.next() {
        Some(addr) => Ok(addr),
        None => bail!("Couldn't resolve QUIC locator address: {}", address),
    }
}
