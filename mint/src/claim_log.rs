//! One line per decided claim. Support reads it from the host.
//!
//! The line is the name, the payment, and `registered`, `refund queued`,
//! `refund sent`, or `kept`, plus the reason when there is one. A sent
//! refund also names its transaction. The access code is not a field.
//!
//! The line is appended to the state disk and written to the serial
//! console. `/metrics` reprints the recent lines, and boot loads those
//! lines back from the file. Loading the file does not queue a refund
//! and does not register a name. A payment that confirmed while the
//! mint was down is still unanswered.

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tokio::sync::watch;
use zcash_primitives::transaction::TxId;

use crate::mint::Name;

/// Lines reprinted on `/metrics`. The file keeps every line.
const RECENT: usize = 64;

/// The state disk. The guest's working directory is `/state`.
const FILE: &str = "/state/log/claims.log";

/// Why a claim was not registered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimReason {
    WrongCode,
    MissingCode,
    Underpaid,
    NameTaken,
    NotAuthorized,
}

impl ClaimReason {
    /// The words support greps for. None of them is an access code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WrongCode => "wrong code",
            Self::MissingCode => "missing code",
            Self::Underpaid => "underpaid",
            Self::NameTaken => "name taken",
            Self::NotAuthorized => "not authorized",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "wrong code" => Self::WrongCode,
            "missing code" => Self::MissingCode,
            "underpaid" => Self::Underpaid,
            "name taken" => Self::NameTaken,
            "not authorized" => Self::NotAuthorized,
            _ => return None,
        })
    }
}

/// What the mint did with the payment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimOutcome {
    Registered,
    RefundQueued,
    RefundSent,
    Kept,
}

impl ClaimOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::RefundQueued => "refund queued",
            Self::RefundSent => "refund sent",
            Self::Kept => "kept",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "registered" => Self::Registered,
            "refund queued" => Self::RefundQueued,
            "refund sent" => Self::RefundSent,
            "kept" => Self::Kept,
            _ => return None,
        })
    }
}

struct Entry {
    index: u64,
    name: String,
    payment: String,
    outcome: ClaimOutcome,
    reason: Option<ClaimReason>,
    refund: Option<String>,
}

struct State {
    path: PathBuf,
    next: u64,
    recent: VecDeque<Entry>,
}

static STATE: Mutex<State> = Mutex::new(State {
    path: PathBuf::new(),
    next: 1,
    recent: VecDeque::new(),
});

static PAGE: std::sync::LazyLock<watch::Sender<String>> =
    std::sync::LazyLock::new(|| watch::channel(String::new()).0);

/// Reads the state-disk lines into the recent gauge. Does not queue a
/// refund and does not register a name.
pub fn load() {
    let mut state = STATE.lock().expect("claim log");
    if state.path.as_os_str().is_empty() {
        state.path = PathBuf::from(FILE);
    }
    let loaded = read_entries(&state.path);
    state.next = loaded.back().map(|entry| entry.index + 1).unwrap_or(1);
    state.recent = loaded;
    publish(&state);
}

/// Appends one decided claim. `refund` is the refund transaction, and
/// only a sent refund has one.
pub fn record(
    name: &Name,
    payment: TxId,
    outcome: ClaimOutcome,
    reason: Option<ClaimReason>,
    refund: Option<TxId>,
) {
    let mut state = STATE.lock().expect("claim log");
    if state.path.as_os_str().is_empty() {
        state.path = PathBuf::from(FILE);
    }
    let index = state.next;
    state.next += 1;
    let line = format_line(
        name.as_str(),
        &payment.to_string(),
        outcome,
        reason,
        refund.as_ref(),
    );
    if let Err(error) = append(&state.path, &line) {
        tracing::warn!(%error, "claim line not written");
    }
    state.recent.push_back(Entry {
        index,
        name: name.as_str().to_string(),
        payment: payment.to_string(),
        outcome,
        reason,
        refund: refund.map(|txid| txid.to_string()),
    });
    while state.recent.len() > RECENT {
        state.recent.pop_front();
    }
    publish(&state);
    drop(state);
    tracing::info!("{line}");
    write_console(&line);
}

/// The recent lines, as a gauge. Empty when no claim has been decided.
pub fn exposition() -> String {
    PAGE.borrow().clone()
}

fn publish(state: &State) {
    PAGE.send_replace(render(&state.recent));
}

fn render(recent: &VecDeque<Entry>) -> String {
    if recent.is_empty() {
        return String::new();
    }
    let mut page = String::from("# TYPE zns_mint_claim_decision gauge\n");
    for entry in recent {
        page.push_str(&format!(
            "zns_mint_claim_decision{{{}}} {}\n",
            labels(entry),
            entry.index
        ));
    }
    page
}

fn labels(entry: &Entry) -> String {
    let mut labels = format!(
        "name=\"{}\",payment=\"{}\",outcome=\"{}\"",
        entry.name,
        entry.payment,
        entry.outcome.as_str()
    );
    if let Some(reason) = entry.reason {
        labels.push_str(&format!(",reason=\"{}\"", reason.as_str()));
    }
    if let Some(refund) = &entry.refund {
        labels.push_str(&format!(",refund=\"{refund}\""));
    }
    labels
}

fn format_line(
    name: &str,
    payment: &str,
    outcome: ClaimOutcome,
    reason: Option<ClaimReason>,
    refund: Option<&TxId>,
) -> String {
    let mut line = format!(
        "claim name={name} payment={payment} outcome=\"{}\"",
        outcome.as_str()
    );
    if let Some(reason) = reason {
        line.push_str(&format!(" reason=\"{}\"", reason.as_str()));
    }
    if let Some(refund) = refund {
        line.push_str(&format!(" refund={refund}"));
    }
    line
}

fn append(path: &Path, line: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{line}")
}

fn read_entries(path: &Path) -> VecDeque<Entry> {
    let Ok(file) = std::fs::File::open(path) else {
        return VecDeque::new();
    };
    let mut entries = VecDeque::new();
    let mut index = 1u64;
    for line in BufReader::new(file).lines() {
        let Ok(line) = line else {
            continue;
        };
        let Some(entry) = parse_line(index, &line) else {
            continue;
        };
        index += 1;
        entries.push_back(entry);
        while entries.len() > RECENT {
            entries.pop_front();
        }
    }
    entries
}

fn parse_line(index: u64, line: &str) -> Option<Entry> {
    let rest = line.strip_prefix("claim ")?;
    let fields = fields(rest)?;
    let name = fields.get("name")?.to_string();
    let payment = fields.get("payment")?.to_string();
    let outcome = ClaimOutcome::parse(fields.get("outcome")?)?;
    let reason = match fields.get("reason") {
        Some(text) => Some(ClaimReason::parse(text)?),
        None => None,
    };
    let refund = fields.get("refund").map(ToString::to_string);
    if !name.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return None;
    }
    Some(Entry {
        index,
        name,
        payment,
        outcome,
        reason,
        refund,
    })
}

/// `key=value` fields. A value in quotes may contain spaces.
fn fields(text: &str) -> Option<std::collections::BTreeMap<&str, &str>> {
    let mut fields = std::collections::BTreeMap::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && bytes[index] == b' ' {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }
        let key_start = index;
        while index < bytes.len() && bytes[index] != b'=' {
            index += 1;
        }
        if index >= bytes.len() {
            return None;
        }
        let key = &text[key_start..index];
        index += 1;
        let value = if index < bytes.len() && bytes[index] == b'"' {
            index += 1;
            let start = index;
            while index < bytes.len() && bytes[index] != b'"' {
                index += 1;
            }
            if index >= bytes.len() {
                return None;
            }
            let value = &text[start..index];
            index += 1;
            value
        } else {
            let start = index;
            while index < bytes.len() && bytes[index] != b' ' {
                index += 1;
            }
            &text[start..index]
        };
        if key.is_empty() || value.is_empty() {
            return None;
        }
        fields.insert(key, value);
    }
    Some(fields)
}

/// The host saves the guest serial console. The mint's own stdout is
/// the log file on the state disk, so this line is written to the
/// console device as well.
#[cfg(not(test))]
fn write_console(line: &str) {
    let Ok(mut console) = OpenOptions::new().write(true).open("/dev/console") else {
        return;
    };
    let _ = writeln!(console, "{line}");
}

#[cfg(test)]
fn write_console(_line: &str) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn payment(byte: u8) -> TxId {
        TxId::from_bytes([byte; 32])
    }

    #[test]
    fn a_line_names_the_payment_and_not_an_access_code() {
        let line = format_line(
            "alice",
            &payment(1).to_string(),
            ClaimOutcome::RefundQueued,
            Some(ClaimReason::WrongCode),
            None,
        );
        assert!(line.contains("outcome=\"refund queued\""));
        assert!(line.contains("reason=\"wrong code\""));
        assert!(!line.contains("code="));
        assert!(parse_line(1, &line).is_some());
        let kept = format_line(
            "alice",
            &payment(2).to_string(),
            ClaimOutcome::Kept,
            Some(ClaimReason::NotAuthorized),
            None,
        );
        assert!(kept.contains("outcome=\"kept\""));
        assert!(kept.contains("reason=\"not authorized\""));
    }

    #[test]
    fn a_sent_refund_names_its_transaction() {
        let refund = payment(9);
        let line = format_line(
            "alice",
            &payment(1).to_string(),
            ClaimOutcome::RefundSent,
            Some(ClaimReason::MissingCode),
            Some(&refund),
        );
        let entry = parse_line(4, &line).unwrap();
        assert_eq!(entry.refund.as_deref(), Some(refund.to_string().as_str()));
        assert_eq!(entry.outcome, ClaimOutcome::RefundSent);
        let page = render(&VecDeque::from([entry]));
        assert!(page.contains("outcome=\"refund sent\""));
        assert!(page.contains(&format!("refund=\"{refund}\"")));
        assert!(page.contains("zns_mint_claim_decision{"));
        assert!(page.ends_with(" 4\n"));
    }

    #[test]
    fn boot_reloads_the_recent_lines_and_does_not_add_one() {
        let dir = std::env::temp_dir().join(format!(
            "zns-claim-log-{}-{}",
            std::process::id(),
            payment(3)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("claims.log");
        let first = format_line(
            "alice",
            &payment(1).to_string(),
            ClaimOutcome::Registered,
            None,
            None,
        );
        let second = format_line(
            "bob",
            &payment(2).to_string(),
            ClaimOutcome::Kept,
            Some(ClaimReason::Underpaid),
            None,
        );
        append(&path, &first).unwrap();
        append(&path, &second).unwrap();
        append(&path, "claim name=alice payment=abc outcome=\"nope\"").unwrap();
        let loaded = read_entries(&path);
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].outcome, ClaimOutcome::Registered);
        assert!(loaded[0].reason.is_none());
        assert_eq!(loaded[1].reason, Some(ClaimReason::Underpaid));
        assert_eq!(loaded[1].index, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
