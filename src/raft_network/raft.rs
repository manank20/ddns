use actix_web::post;
use actix_web::web::Data;
use actix_web::web::Json;
use actix_web::Responder;
use openraft::raft::AppendEntriesRequest;
use openraft::raft::InstallSnapshotRequest;
use openraft::raft::VoteRequest;

use crate::raft_messages::RaftDNS;
use crate::NodeId;
use crate::TypeConfig;

// --- Raft communication

#[post("/raft-vote")]
pub async fn vote(
    app: Data<RaftDNS>,
    req: Json<VoteRequest<NodeId>>,
) -> actix_web::Result<impl Responder> {
    let res = app.raft.vote(req.0).await;
    Ok(Json(res))
}

#[post("/raft-append")]
pub async fn append(
    app: Data<RaftDNS>,
    req: Json<AppendEntriesRequest<TypeConfig>>,
) -> actix_web::Result<impl Responder> {
    let res = app.raft.append_entries(req.0).await;
    Ok(Json(res))
}

#[post("/raft-snapshot")]
pub async fn snapshot(
    app: Data<RaftDNS>,
    req: Json<InstallSnapshotRequest<TypeConfig>>,
) -> actix_web::Result<impl Responder> {
    let res = app.raft.install_snapshot(req.0).await;
    Ok(Json(res))
}
