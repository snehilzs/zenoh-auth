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
use crate::net::routing::interceptor::authz::{PolicyEnforcer, ZAuth};
use casbin::prelude::*;

use self::authz::Action;

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
    /*
       this is the singleton for interceptors
       all init code for AC should be called here
       example, for casbin we are using the enforecer init here
       for in-built AC, we will load the policy rules here and also set the parameters (type of policy etc)
    */
    println!("the interceptor is initialized");

    let policy_enforcer =
        PolicyEnforcer::init_policy("pol_string".to_owned()).expect("enforcer not init");

    //  let e = async_std::task::block_on(async { authz::start_authz().await.unwrap() });
    //store the enforcer instance for use in rest of the sessions
    vec![Box::new(AclEnforcer { e: policy_enforcer })]
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

pub(crate) struct AclEnforcer {
    e: PolicyEnforcer,
}

impl InterceptorTrait for AclEnforcer {
    fn new_transport_unicast(
        &self,
        transport: &TransportUnicast,
    ) -> (Option<IngressIntercept>, Option<EgressIntercept>) {
        let e = &self.e;
        /* */
        let usr = transport.get_zid();
        (
            Some(Box::new(IngressAclEnforcer { e: Some(e) })),
            Some(Box::new(EgressAclEnforcer {
                zid: usr.unwrap().to_string(),
                e: None,
            })),
        )
    }

    fn new_transport_multicast(&self, _transport: &TransportMulticast) -> Option<EgressIntercept> {
        let e = &self.e;

        Some(Box::new(IngressAclEnforcer { e: None }))
    }

    fn new_peer_multicast(&self, _transport: &TransportMulticast) -> Option<IngressIntercept> {
        let e = &self.e;
        Some(Box::new(IngressAclEnforcer { e: None }))
    }
}

pub(crate) struct IngressAclEnforcer {
    e: Option<PolicyEnforcer>,
}

impl InterceptTrait for IngressAclEnforcer {
    fn intercept(
        &self,
        ctx: RoutingContext<NetworkMessage>,
    ) -> Option<RoutingContext<NetworkMessage>> {
        // let e = async_std::task::block_on(async { authz::start_authz().await.unwrap() });
        let e = self.e?; //.unwrap();
                         //how to get enforcer here without
                         //pass code to PEP

        // println!("print ingress ctx body: {:?}", ctx.msg.body.clone());
        //  println!("print push-payload: {:?}", ctx.msg.body.clone());

        //send msg to PEP

        if let NetworkBody::Push(push) = ctx.msg.body {
            if let zenoh_protocol::zenoh::PushBody::Put(_put) = push.payload {
                let act = Action::WRITE;
                let decision = e.policy_enforcement_point(ctx, act).unwrap();

                let ke = ctx.full_expr().unwrap();
                let zid = ctx.inface().unwrap().state.zid;
                if decision {
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
    e: Option<PolicyEnforcer>,
    zid: String,
}

impl InterceptTrait for EgressAclEnforcer {
    fn intercept(
        &self,
        ctx: RoutingContext<NetworkMessage>,
    ) -> Option<RoutingContext<NetworkMessage>> {
        // let e = async_std::task::block_on(async { authz::start_authz().await.unwrap() });
        println!("print egress ctx body: {:?}", ctx.msg.body.clone());
        let e = self.e?;

        if let NetworkBody::Push(push) = ctx.msg.body.clone() {
            if let zenoh_protocol::zenoh::PushBody::Put(_put) = push.payload {
                //get zid, ke and action and then check for permissions
                let ke = ctx.full_expr().unwrap();
                let zid = &self.zid;
                let act = "GET";
                // if e.authz_testing(zid.to_string(), ke.to_owned(), act.to_owned())
                //     .unwrap()
                // {
                //     //allowed the request
                //     println!("{} can {} on {}", zid, act, ke);
                // } else {
                //     // denyied the request
                //     println!("{} cannot {} on {}", zid, act, ke);
                //     return None;
                // }
            }
        }
        Some(ctx)
    }
}
