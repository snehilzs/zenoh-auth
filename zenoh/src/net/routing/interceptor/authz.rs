// use casbin::{CoreApi, Enforcer};
use casbin::prelude::*;
use zenoh_result::ZResult;
pub trait ZAuth {
    fn authz_testing(&self, _: String, _: String, _: String) -> ZResult<bool>;
}

impl ZAuth for Enforcer {
    fn authz_testing(&self, zid: String, ke: String, act: String) -> ZResult<bool> {
        // let usr = "uid_1"; // the user that wants to access a resource.
        // let keyexpr = "demo/info/resource1"; // the resource that is going to be accessed.
        // let act = "PUB"; // the operation that the user performs on the resource.

        /*
        these values should be extraced from the authn code.
        has to be atomic, to avoid another process sending fake info
         */

        if let Ok(authorized) = self.enforce((zid.clone(), ke.clone(), act.clone())) {
            if authorized {
                //allow the request
                println!("{} can {} on {}", zid, act, ke);
            } else {
                // deny the request
                println!("{} cannot {} on {}", zid, act, ke);
            }
            Ok(authorized)
        } else {
            println!("policy enforcement error");
            Ok(false)
        }
    }
}

pub async fn start_authz() -> Result<Enforcer> {
    println!("testing casbin");
    println!("{}", std::env::current_dir().unwrap().display());
    let mut e = Enforcer::new("keymatch_model.conf", "keymatch_policy.csv").await?;
    // e.enable_log(true);
    Ok(e)
}
