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
use super::face::FaceState;
pub use super::pubsub::*;
pub use super::queries::*;
pub use super::resource::*;
use crate::net::routing::hat;
use crate::net::routing::hat::HatTrait;
use crate::net::routing::interceptor::interceptors;
use crate::net::routing::interceptor::Interceptor;
use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::sync::{Mutex, RwLock};
use std::time::Duration;
use uhlc::HLC;
use zenoh_protocol::core::{ExprId, WhatAmI, ZenohId};
use zenoh_protocol::network::Mapping;
#[cfg(feature = "stats")]
use zenoh_transport::stats::TransportStats;
// use zenoh_collections::Timer;
use zenoh_sync::get_mut_unchecked;

pub(crate) struct RoutingExpr<'a> {
    pub(crate) prefix: &'a Arc<Resource>,
    pub(crate) suffix: &'a str,
    full: Option<String>,
}

impl<'a> RoutingExpr<'a> {
    #[inline]
    pub(crate) fn new(prefix: &'a Arc<Resource>, suffix: &'a str) -> Self {
        RoutingExpr {
            prefix,
            suffix,
            full: None,
        }
    }

    #[inline]
    pub(crate) fn full_expr(&mut self) -> &str {
        if self.full.is_none() {
            self.full = Some(self.prefix.expr() + self.suffix);
        }
        self.full.as_ref().unwrap()
    }
}

pub struct Tables {
    pub(crate) zid: ZenohId,
    pub(crate) whatami: WhatAmI,
    pub(crate) face_counter: usize,
    #[allow(dead_code)]
    pub(crate) hlc: Option<Arc<HLC>>,
    pub(crate) drop_future_timestamp: bool,
    // pub(crate) timer: Timer,
    // pub(crate) queries_default_timeout: Duration,
    pub(crate) root_res: Arc<Resource>,
    pub(crate) faces: HashMap<usize, Arc<FaceState>>,
    pub(crate) mcast_groups: Vec<Arc<FaceState>>,
    pub(crate) mcast_faces: Vec<Arc<FaceState>>,
    pub(crate) interceptors: Vec<Interceptor>,
    pub(crate) pull_caches_lock: Mutex<()>,
    pub(crate) hat: Box<dyn Any + Send + Sync>,
    pub(crate) hat_code: Arc<dyn HatTrait + Send + Sync>, // TODO make this a Box
}

impl Tables {
    pub fn new(
        zid: ZenohId,
        whatami: WhatAmI,
        hlc: Option<Arc<HLC>>,
        drop_future_timestamp: bool,
        router_peers_failover_brokering: bool,
        _queries_default_timeout: Duration,
    ) -> Self {
        let hat_code = hat::new_hat(whatami);
        Tables {
            zid,
            whatami,
            face_counter: 0,
            hlc,
            drop_future_timestamp,
            // timer: Timer::new(true),
            // queries_default_timeout,
            root_res: Resource::root(),
            faces: HashMap::new(),
            mcast_groups: vec![],
            mcast_faces: vec![],
            interceptors: interceptors(),
            pull_caches_lock: Mutex::new(()),
            hat: hat_code.new_tables(router_peers_failover_brokering),
            hat_code: hat_code.into(),
        }
    }

    #[doc(hidden)]
    pub fn _get_root(&self) -> &Arc<Resource> {
        &self.root_res
    }

    pub fn print(&self) -> String {
        Resource::print_tree(&self.root_res)
    }

    #[inline]
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub(crate) fn get_mapping<'a>(
        &'a self,
        face: &'a FaceState,
        expr_id: &ExprId,
        mapping: Mapping,
    ) -> Option<&'a Arc<Resource>> {
        match expr_id {
            0 => Some(&self.root_res),
            expr_id => face.get_mapping(expr_id, mapping),
        }
    }

    #[inline]
    pub(crate) fn get_face(&self, zid: &ZenohId) -> Option<&Arc<FaceState>> {
        self.faces.values().find(|face| face.zid == *zid)
    }

    fn compute_routes(&mut self, res: &mut Arc<Resource>) {
        self.hat_code.clone().compute_data_routes(self, res);
        self.hat_code.clone().compute_query_routes(self, res);
    }

    pub(crate) fn compute_matches_routes(&mut self, res: &mut Arc<Resource>) {
        if res.context.is_some() {
            self.compute_routes(res);

            let resclone = res.clone();
            for match_ in &mut get_mut_unchecked(res).context_mut().matches {
                let match_ = &mut match_.upgrade().unwrap();
                if !Arc::ptr_eq(match_, &resclone) && match_.context.is_some() {
                    self.compute_routes(match_);
                }
            }
        }
    }
}

pub fn close_face(tables: &TablesLock, face: &Weak<FaceState>) {
    match face.upgrade() {
        Some(mut face) => {
            log::debug!("Close {}", face);
            finalize_pending_queries(tables, &mut face);
            zlock!(tables.ctrl_lock).close_face(tables, &mut face);
        }
        None => log::error!("Face already closed!"),
    }
}

pub struct TablesLock {
    pub tables: RwLock<Tables>,
    pub(crate) ctrl_lock: Mutex<Box<dyn HatTrait + Send + Sync>>,
    pub queries_lock: RwLock<()>,
}
