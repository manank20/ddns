use crate::Raft;
use crate::NodeID;
use crate::Store;

use std::sync::Arc;


pub struct RaftDNS {
    pub id: NodeID,
    pub addr: SocketAddr,
    pub raft: Raft,
    pub store: Arc<Store>,
    pub config: Arc<openraft::Config>,
}