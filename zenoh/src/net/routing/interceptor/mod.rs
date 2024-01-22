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
//! This module is intended for Zenoh's internal use.
//!
//! [Click here for Zenoh's documentation](../zenoh/index.html)
use crate::net::routing::interceptor::authz::ZAuth;

use super::RoutingContext;
//use zenoh_config::WhatAmI;
use zenoh_protocol::network::{NetworkBody, NetworkMessage};
use zenoh_transport::{TransportMulticast, TransportUnicast};
mod authz;
//use crate::net::routing::;
pub(crate) trait InterceptTrait {
    fn intercept(
        &self,
        ctx: RoutingContext<NetworkMessage>,
    ) -> Option<RoutingContext<NetworkMessage>>;
}

pub(crate) type Intercept = Box<dyn InterceptTrait + Send + Sync>;
pub(crate) type IngressIntercept = Intercept;
pub(crate) type EgressIntercept = Intercept;

pub(crate) trait InterceptorTrait {
    fn new_transport_unicast(
        &self,
        transport: &TransportUnicast,
    ) -> (Option<IngressIntercept>, Option<EgressIntercept>);
    fn new_transport_multicast(&self, transport: &TransportMulticast) -> Option<EgressIntercept>;
    fn new_peer_multicast(&self, transport: &TransportMulticast) -> Option<IngressIntercept>;
}

pub(crate) type Interceptor = Box<dyn InterceptorTrait + Send + Sync>;

pub(crate) fn interceptors() -> Vec<Interceptor> {
    // Add interceptors here
    println!("interceptor setting up the session");
    vec![Box::new(AclEnforcer {})]
    // vec![Box::new(LoggerInterceptor {})]

    //vec![]
}

pub(crate) struct InterceptsChain {
    pub(crate) intercepts: Vec<Intercept>,
}

impl InterceptsChain {
    #[allow(dead_code)]
    pub(crate) fn empty() -> Self {
        Self { intercepts: vec![] }
    }
}

impl From<Vec<Intercept>> for InterceptsChain {
    fn from(intercepts: Vec<Intercept>) -> Self {
        InterceptsChain { intercepts }
    }
}

impl InterceptTrait for InterceptsChain {
    fn intercept(
        &self,
        mut ctx: RoutingContext<NetworkMessage>,
    ) -> Option<RoutingContext<NetworkMessage>> {
        for intercept in &self.intercepts {
            match intercept.intercept(ctx) {
                Some(newctx) => {
                    ctx = newctx;
                }
                None => {
                    log::trace!("Msg intercepted!");
                    return None;
                }
            }
        }
        Some(ctx)
    }
}

pub(crate) struct AclEnforcer {}

impl InterceptorTrait for AclEnforcer {
    fn new_transport_unicast(
        &self,
        transport: &TransportUnicast,
    ) -> (Option<IngressIntercept>, Option<EgressIntercept>) {
        let usr = transport.get_zid();
        (
            Some(Box::new(IngressAclEnforcer {})),
            Some(Box::new(EgressAclEnforcer {
                zid: usr.unwrap().to_string(),
            })),
        )
    }

    fn new_transport_multicast(&self, _transport: &TransportMulticast) -> Option<EgressIntercept> {
        Some(Box::new(IngressAclEnforcer {}))
    }

    fn new_peer_multicast(&self, _transport: &TransportMulticast) -> Option<IngressIntercept> {
        Some(Box::new(IngressAclEnforcer {}))
    }
}

pub(crate) struct IngressAclEnforcer {}

impl InterceptTrait for IngressAclEnforcer {
    fn intercept(
        &self,
        ctx: RoutingContext<NetworkMessage>,
    ) -> Option<RoutingContext<NetworkMessage>> {
        let e = async_std::task::block_on(async { authz::start_authz().await.unwrap() });

        //how to get enforcer here without
        //pass code to PEP

        if let NetworkBody::Push(push) = ctx.msg.body.clone() {
            if let zenoh_protocol::zenoh::PushBody::Put(_put) = push.payload {
                //get zid, keyexp and action and then check for permissions
                let ke = ctx.full_expr().unwrap();
                let zid = ctx.inface().unwrap().state.zid;
                let act = "PUT";
                if e.authz_testing(zid.to_string(), ke.to_owned(), act.to_owned())
                    .unwrap()
                {
                    //allowed the request
                    println!("{} can {} on {}", zid, act, ke);
                } else {
                    // denied the request
                    println!("{} cannot {} on {}", zid, act, ke);
                    return None;
                }
            }
        }

        Some(ctx)
    }
}

pub(crate) struct EgressAclEnforcer {
    zid: String,
}

impl InterceptTrait for EgressAclEnforcer {
    fn intercept(
        &self,
        ctx: RoutingContext<NetworkMessage>,
    ) -> Option<RoutingContext<NetworkMessage>> {
        let e = async_std::task::block_on(async { authz::start_authz().await.unwrap() });

        if let NetworkBody::Push(push) = ctx.msg.body.clone() {
            if let zenoh_protocol::zenoh::PushBody::Put(_put) = push.payload {
                //get zid, ke and action and then check for permissions
                let ke = ctx.full_expr().unwrap();
                let zid = &self.zid;
                let act = "GET";
                if e.authz_testing(zid.to_string(), ke.to_owned(), act.to_owned())
                    .unwrap()
                {
                    //allowed the request
                    println!("{} can {} on {}", zid, act, ke);
                } else {
                    // denyied the request
                    println!("{} cannot {} on {}", zid, act, ke);
                    return None;
                }
            }
        }

        Some(ctx)
    }
}
