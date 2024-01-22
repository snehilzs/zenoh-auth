// use casbin::{CoreApi, Enforcer};
use casbin::prelude::*;
use zenoh_result::ZResult;
pub trait ZAuth {
    fn authz_testing(&self, _: String, _: String, _: String) -> ZResult<bool>;
}

impl ZAuth for Enforcer {
    fn authz_testing(&self, zid: String, ke: String, act: String) -> ZResult<bool> {
        /*
        (zid, keyexpr, act): these values should be extraced from the authn code.
        has to be atomic, to avoid another process sending the wrong info
         */

        if let Ok(authorized) = self.enforce((zid.clone(), ke.clone(), act.clone())) {
            Ok(authorized)
        } else {
            println!("policy enforcement error");
            Ok(false)
        }
    }
}

pub async fn policy_enforcement_point() {}

pub async fn policy_decision_point() {}

pub async fn policy_resource_point() {
    //add management API features here
    //loading policy from file/network etc
}
pub async fn start_authz() -> Result<Enforcer> {
    // get file value
    let mut e = Enforcer::new("keymatch_model.conf", "keymatch_policy.csv").await?;
    e.enable_log(true);
    Ok(e)
}
