use std::collections::BTreeMap;
use std::collections::BTreeSet;

use actix_web::get;
use actix_web::post;
use actix_web::web::Data;
use actix_web::web::Json;
use actix_web::Responder;
use openraft::error::Infallible;
use openraft::BasicNode;
use openraft::RaftMetrics;

use crate::raft_messages::RaftDNS;
use crate::NodeId;

// --- Cluster management

/// Add a node as **Learner**.
#[post("/add-learner")]
pub async fn add_learner(app: Data<RaftDNS>, req: Json<(NodeId, String)>) -> actix_web::Result<impl Responder> {
    let node_id = req.0 .0;
    let node = BasicNode { addr: req.0 .1.clone() };
    let res = app.raft.add_learner(node_id, node, true).await;
    Ok(Json(res))
}

/// Changes specified learners to members, or remove members.
#[post("/change-membership")]
pub async fn change_membership(app: Data<RaftDNS>, req: Json<BTreeSet<NodeId>>) -> actix_web::Result<impl Responder> {
    let res = app.raft.change_membership(req.0, false).await;
    Ok(Json(res))
}

/// Initialize a single-node cluster.
#[post("/init")]
pub async fn init(app: Data<RaftDNS>) -> actix_web::Result<impl Responder> {
    let mut nodes = BTreeMap::new();
    nodes.insert(app.id, BasicNode { addr: app.addr.clone() });
    let res = app.raft.initialize(nodes).await;
    Ok(Json(res))
}

/// Get the latest metrics of the cluster
#[get("/metrics")]
pub async fn metrics(app: Data<RaftDNS>) -> actix_web::Result<impl Responder> {
    let metrics = app.raft.metrics().borrow().clone();

    let res: Result<RaftMetrics<NodeId, BasicNode>, Infallible> = Ok(metrics);
    Ok(Json(res))
}