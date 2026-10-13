pub mod isolation;
// Trusted authorization and bounded execution. Native execution unavailable.
use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request as CedarRequest,
};
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

pub const MAX_BODY: usize = 32_768;
type HmacSha256 = Hmac<Sha256>;
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Signed {
    pub payload: String,
    pub mac: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub operation: String,
    pub resource: String,
    pub approval: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    pub task_id: String,
    pub capability_id: String,
    pub session_id: String,
    pub expires_at: u64,
    pub grants: Vec<Grant>,
    #[serde(default)]
    pub protected_resources: Vec<String>,
}

/// Trusted bootstrap is supplied by the supervisor before the agent gets a channel.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    pub key_hex: String,
    pub contract: Signed,
    pub files: BTreeMap<String, String>,
    pub apis: BTreeMap<String, String>,
    #[serde(default)]
    pub isolated: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRequest {
    pub task_id: String,
    pub capability_id: String,
    pub operation: String,
    pub resource: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub approval: Option<Signed>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub task_id: String,
    pub capability_id: String,
    pub session_id: String,
    pub operation: String,
    pub resource: String,
    pub body_sha256: String,
    pub nonce: String,
    pub expires_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub event_id: i64,
    pub decision: String,
    pub reason: String,
    pub executed: bool,
    pub data: Option<String>,
    pub provenance: Option<String>,
    pub authorization_ns: Option<u64>,
}

pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 80
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Reject ambiguous paths instead of normalizing them into a different authority.
pub fn valid_resource(op: &str, s: &str) -> bool {
    if s.is_empty() || s.len() > 240 {
        return false;
    }
    if op == "api_get" || op == "api_post" || op == "wasm_run" {
        // An opaque fixture identifier, never a URL, DNS name, or socket address.
        return s.starts_with("sim:") && identifier(&s[4..]);
    }
    if op == "isolated_read" || op == "isolated_write" {
        return matches!(s, "input.txt" | "output.txt");
    }
    if op != "read_file" && op != "write_file" {
        return false;
    }
    s.split('/').all(|part| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    })
}

fn sensitive(s: &str) -> bool {
    s.split('/').any(|p| {
        matches!(
            p.to_ascii_lowercase().as_str(),
            ".env" | ".git" | "secrets" | "credentials"
        )
    })
}

fn verify<T: for<'de> Deserialize<'de>>(key: &[u8], domain: &[u8], signed: &Signed) -> Result<T> {
    let mut mac = HmacSha256::new_from_slice(key)?;
    mac.update(domain);
    mac.update(signed.payload.as_bytes());
    mac.verify_slice(&hex::decode(&signed.mac)?)?;
    Ok(serde_json::from_str(&signed.payload)?)
}

pub struct Engine {
    contract: Contract,
    key: Vec<u8>,
    files: BTreeMap<String, String>,
    apis: BTreeMap<String, String>,
    db: Connection,
    policies: PolicySet,
    isolated: Option<(tempfile::TempDir, isolation::PinnedFiles)>,
    wasm: Option<isolation::WasmTool>,
    tainted: bool,
}

impl Engine {
    pub fn new(boot: Bootstrap, db: Connection, timestamp: u64) -> Result<Self> {
        let key = hex::decode(boot.key_hex)?;
        if key.len() != 32 {
            return Err("invalid key length".into());
        }
        let contract: Contract = verify(&key, b"sentinel-contract-v1\0", &boot.contract)?;
        if !identifier(&contract.task_id)
            || !identifier(&contract.capability_id)
            || !identifier(&contract.session_id)
            || contract.expires_at <= timestamp
            || contract.expires_at > timestamp.saturating_add(3600)
            || contract.grants.len() > 64
        {
            return Err("invalid contract".into());
        }
        let mut seen = HashSet::new();
        for g in &contract.grants {
            if !valid_resource(&g.operation, &g.resource)
                || !seen.insert((&g.operation, &g.resource))
            {
                return Err("invalid grant".into());
            }
        }
        if boot.files.len() + boot.apis.len() > 128
            || boot
                .files
                .values()
                .chain(boot.apis.values())
                .any(|v| v.len() > MAX_BODY)
            || boot.files.keys().any(|k| !valid_resource("read_file", k))
            || boot.apis.keys().any(|k| !valid_resource("api_get", k))
        {
            return Err("invalid fixture".into());
        }
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS used_approvals(session TEXT NOT NULL, nonce TEXT NOT NULL,
                PRIMARY KEY(session, nonce));
            CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, timestamp INTEGER NOT NULL,
                task TEXT NOT NULL, operation TEXT NOT NULL, decision TEXT NOT NULL,
                reason TEXT NOT NULL, executed INTEGER NOT NULL DEFAULT 0);",
        )?;
        let policies = PolicySet::from_str(include_str!("../../policies/task.cedar"))?;
        let isolated = if boot.isolated {
            isolation::pinned_fixture()?
        } else {
            None
        };
        let wasm = if boot.isolated {
            Some(isolation::WasmTool::new()?)
        } else {
            None
        };
        Ok(Self {
            isolated,
            wasm,
            tainted: false,
            contract,
            key,
            files: boot.files,
            apis: boot.apis,
            db,
            policies,
        })
    }

    fn audit(&self, timestamp: u64, op: &str, decision: &str, reason: &str) -> Result<i64> {
        // Only trusted identifiers and enumerated labels. Never raw paths, bodies or tokens.
        self.db.execute(
            "INSERT INTO audit(timestamp,task,operation,decision,reason) VALUES(?,?,?,?,?)",
            params![timestamp, self.contract.task_id, op, decision, reason],
        )?;
        Ok(self.db.last_insert_rowid())
    }

    fn reject(&self, timestamp: u64, op: &str, decision: &str, reason: &str) -> Result<Response> {
        let event_id = self.audit(timestamp, op, decision, reason)?;
        Ok(Response {
            event_id,
            decision: decision.into(),
            reason: reason.into(),
            executed: false,
            data: None,
            provenance: None,
            authorization_ns: None,
        })
    }

    pub fn malformed(&self, timestamp: u64) -> Result<Response> {
        self.reject(timestamp, "invalid", "DENY", "malformed_request")
    }

    /// Production entry point obtains time from the runtime, never the request.
    pub fn execute(&mut self, req: ToolRequest) -> Result<Response> {
        self.execute_at(req, now()?)
    }

    fn execute_at(&mut self, req: ToolRequest, timestamp: u64) -> Result<Response> {
        let started = std::time::Instant::now();
        let op = match req.operation.as_str() {
            "read_file" | "write_file" | "api_get" | "api_post" | "isolated_read"
            | "isolated_write" | "wasm_run" => req.operation.as_str(),
            _ => "invalid",
        };
        if req.task_id != self.contract.task_id || req.capability_id != self.contract.capability_id
        {
            return self.reject(timestamp, op, "DENY", "invalid_capability");
        }
        if timestamp >= self.contract.expires_at {
            return self.reject(timestamp, op, "DENY", "expired_contract");
        }
        if !valid_resource(op, &req.resource)
            || req.body.len() > MAX_BODY
            || ((op == "read_file" || op == "api_get" || op == "isolated_read")
                && !req.body.is_empty())
        {
            return self.reject(timestamp, op, "DENY", "invalid_request");
        }
        if sensitive(&req.resource) {
            return self.reject(timestamp, op, "DENY", "sensitive_resource");
        }
        let grant = self
            .contract
            .grants
            .iter()
            .find(|g| g.operation == op && g.resource == req.resource);
        let grant = match grant {
            Some(g) => g,
            None => return self.reject(timestamp, op, "DENY", "out_of_scope"),
        };
        if self.tainted
            && matches!(
                op,
                "api_post" | "write_file" | "isolated_write" | "wasm_run"
            )
        {
            return self.reject(timestamp, op, "DENY", "protected_flow_blocked");
        }
        let mut nonce = None;
        if grant.approval {
            let signed = match &req.approval {
                Some(s) => s,
                None => return self.reject(timestamp, op, "REQUIRE_APPROVAL", "approval_required"),
            };
            let approval = verify::<Approval>(&self.key, b"sentinel-approval-v1\0", signed);
            let a = match approval {
                Ok(a) => a,
                Err(_) => return self.reject(timestamp, op, "DENY", "invalid_approval"),
            };
            if a.task_id != self.contract.task_id
                || a.capability_id != self.contract.capability_id
                || a.session_id != self.contract.session_id
                || a.operation != op
                || a.resource != req.resource
                || a.body_sha256 != hex::encode(Sha256::digest(req.body.as_bytes()))
                || !identifier(&a.nonce)
                || a.expires_at <= timestamp
                || a.expires_at > self.contract.expires_at
                || a.expires_at > timestamp.saturating_add(300)
            {
                return self.reject(timestamp, op, "DENY", "invalid_approval");
            }
            nonce = Some(a.nonce);
        } else if req.approval.is_some() {
            return self.reject(timestamp, op, "DENY", "unexpected_approval");
        }
        let context = Context::from_json_value(
            serde_json::json!({
                "task_valid": true, "in_scope": true, "approved": true, "sensitive": false
            }),
            None,
        )?;
        let cedar_req = CedarRequest::new(
            EntityUid::from_str("Agent::\"task-agent\"")?,
            EntityUid::from_str(&format!("Action::\"{op}\""))?,
            EntityUid::from_str("Resource::\"validated-resource\"")?,
            context,
            None,
        )?;
        let verdict =
            Authorizer::new().is_authorized(&cedar_req, &self.policies, &Entities::empty());
        // Cedar normally skips individual policy evaluation errors. This gateway denies all errors.
        if verdict.decision() != Decision::Allow || verdict.diagnostics().errors().next().is_some()
        {
            return self.reject(timestamp, op, "DENY", "policy_denied");
        }
        if cfg!(windows) && matches!(op, "isolated_read" | "isolated_write") {
            return self.reject(timestamp, op, "DENY", "unsupported_platform");
        }
        let authorization_ns = started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        // Prepare the outcome before consuming an approval or changing state.
        let data = match op {
            "read_file" => self.files.get(&req.resource).cloned(),
            "write_file" => Some("written".into()),
            "isolated_read" => match &self.isolated {
                Some((_, fs)) => fs.read(&req.resource).ok(),
                None => None,
            },
            "isolated_write" => self
                .isolated
                .as_ref()
                .filter(|_| req.resource == "output.txt")
                .map(|_| "isolated write complete".into()),
            "wasm_run" => self
                .wasm
                .as_ref()
                .filter(|_| req.resource == "sim:checksum")
                .map(|_| "pending".into()),
            "api_get" => self.apis.get(&req.resource).cloned(),
            "api_post" => self
                .apis
                .get(&req.resource)
                .map(|_| "simulated request accepted".into()),
            _ => None,
        };
        let data = match data {
            Some(d) => d,
            None => return self.reject(timestamp, op, "DENY", "missing_fixture"),
        };
        let tx = self.db.transaction()?;
        if let Some(nonce) = nonce {
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO used_approvals(session,nonce) VALUES(?,?)",
                params![self.contract.session_id, nonce],
            )?;
            if inserted == 0 {
                tx.rollback()?;
                return self.reject(timestamp, op, "DENY", "approval_replayed");
            }
        }
        tx.execute(
            "INSERT INTO audit(timestamp,task,operation,decision,reason) VALUES(?,?,?,?,?)",
            params![timestamp, self.contract.task_id, op, "ALLOW", "authorized"],
        )?;
        let event = tx.last_insert_rowid();
        tx.commit()?; // Durable approval consumption and audit intent MUST precede side effects.
        let protected = self.contract.protected_resources.contains(&req.resource);
        let data = match op {
            "isolated_write" => {
                self.isolated
                    .as_ref()
                    .ok_or("isolation unavailable")?
                    .1
                    .write(&req.resource, &req.body)?;
                data
            }
            "wasm_run" => self
                .wasm
                .as_ref()
                .ok_or("isolation unavailable")?
                .run(&req.body)?,
            "write_file" => {
                self.files.insert(req.resource, req.body);
                data
            }
            _ => data,
        };
        if protected && matches!(op, "read_file" | "api_get" | "isolated_read") {
            self.tainted = true;
        }
        self.db
            .execute("UPDATE audit SET executed=1 WHERE id=?", [event])?;
        Ok(Response {
            event_id: event,
            decision: "ALLOW".into(),
            reason: "authorized".into(),
            executed: true,
            data: Some(data),
            provenance: Some(
                if protected {
                    "untrusted_protected_output"
                } else {
                    "untrusted_tool_output"
                }
                .into(),
            ),
            authorization_ns: Some(authorization_ns),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sign<T: Serialize>(value: &T, domain: &[u8]) -> Signed {
        let payload = serde_json::to_string(value).unwrap();
        let mut mac = HmacSha256::new_from_slice(&[7; 32]).unwrap();
        mac.update(domain);
        mac.update(payload.as_bytes());
        Signed {
            payload,
            mac: hex::encode(mac.finalize().into_bytes()),
        }
    }
    fn engine() -> Engine {
        let c = Contract {
            task_id: "t".into(),
            capability_id: "c".into(),
            session_id: "s".into(),
            expires_at: 200,
            protected_resources: vec![],
            grants: vec![Grant {
                operation: "write_file".into(),
                resource: "out.txt".into(),
                approval: false,
            }],
        };
        Engine::new(
            Bootstrap {
                key_hex: hex::encode([7; 32]),
                contract: sign(&c, b"sentinel-contract-v1\0"),
                files: BTreeMap::new(),
                apis: BTreeMap::new(),
                isolated: false,
            },
            Connection::open_in_memory().unwrap(),
            100,
        )
        .unwrap()
    }
    fn req() -> ToolRequest {
        ToolRequest {
            task_id: "t".into(),
            capability_id: "c".into(),
            operation: "write_file".into(),
            resource: "out.txt".into(),
            body: "safe".into(),
            approval: None,
        }
    }
    #[test]
    fn authorization_and_expiry_boundary() {
        let mut e = engine();
        assert!(e.execute_at(req(), 199).unwrap().executed);
        assert_eq!(e.execute_at(req(), 200).unwrap().reason, "expired_contract");
    }
    #[test]
    fn deny_unmatched_action_and_capability() {
        let mut e = engine();
        let mut r = req();
        r.operation = "shell".into();
        assert_eq!(e.execute_at(r, 100).unwrap().decision, "DENY");
        let mut r = req();
        r.capability_id = "forged".into();
        assert_eq!(e.execute_at(r, 100).unwrap().reason, "invalid_capability");
        assert!(e.files.is_empty());
    }
    #[test]
    fn reject_path_ambiguity() {
        for path in [
            "",
            "/etc/passwd",
            "../x",
            "a/../b",
            "a//b",
            "a/./b",
            "a/",
            "a\\b",
            "a%2fb",
            "a\0b",
            "é.txt",
            "C:/x",
        ] {
            assert!(!valid_resource("read_file", path), "{path:?}");
        }
        assert!(valid_resource("read_file", "src/main.rs"));
        assert!(!valid_resource("api_get", "https://example.com"));
    }
    #[test]
    fn audit_failure_prevents_mutation() {
        let mut e = engine();
        e.db.execute_batch("DROP TABLE audit").unwrap();
        assert!(e.execute_at(req(), 100).is_err());
        assert!(e.files.is_empty());
    }
    #[test]
    fn cedar_default_deny_and_error_fail_closed() {
        let mut e = engine();
        e.policies = PolicySet::new();
        assert_eq!(e.execute_at(req(), 100).unwrap().decision, "DENY");
        e.policies = PolicySet::from_str("permit(principal, action, resource); permit(principal, action, resource) when { context.absent };").unwrap();
        assert_eq!(e.execute_at(req(), 100).unwrap().decision, "DENY");
        assert!(e.files.is_empty());
    }
}
