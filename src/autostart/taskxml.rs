//! A scheduled task's XML (`IRegisteredTask::get_Xml`), read with quick-xml's reader only: the
//! logon and boot triggers (with their user), the Exec actions (Command, Arguments), the
//! ComHandler actions (the CLSID), RegistrationInfo's Date and Author, and the Principal's UserId
//! and RunLevel. Pure. The XML comes from a task anyone with rights to register one wrote: sizes
//! are capped, everything is text to be cleaned before it is shown.

use quick_xml::XmlVersion;
use quick_xml::events::Event;

/// The most XML read for one task (the helper caps it on the wire too).
pub const MAX_XML: usize = 256 * 1024;
const MAX_ITEMS: usize = 64;
const MAX_TEXT: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TriggerKind {
    Logon,
    Boot,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trigger {
    pub kind: TriggerKind,
    /// LogonTrigger's UserId: the account whose sign-in starts it (None: anyone's).
    pub user: Option<String>,
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Exec { command: String, args: String },
    ComHandler { clsid: String },
    /// Send-mail and message-box actions (deprecated) and anything newer.
    Other(String),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TaskDef {
    pub date: Option<String>,
    pub author: Option<String>,
    pub triggers: Vec<Trigger>,
    pub actions: Vec<Action>,
    pub user: Option<String>,
    pub run_level: Option<String>,
    /// Settings/Hidden: the task asks not to be shown in Task Scheduler's list.
    pub hidden: bool,
}

impl TaskDef {
    /// An enabled logon or boot trigger: the task starts with the PC.
    pub fn starts_with_pc(&self) -> bool {
        self.triggers.iter().any(|t| t.enabled && matches!(t.kind, TriggerKind::Logon | TriggerKind::Boot))
    }

    /// "at sign-in of DOMAIN\ted", "at sign-in of any user", "at startup".
    pub fn when(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for t in self.triggers.iter().filter(|t| t.enabled) {
            let p = match (t.kind, &t.user) {
                (TriggerKind::Logon, Some(u)) => format!("at sign-in of {u}"),
                (TriggerKind::Logon, None) => "at sign-in of any user".to_string(),
                (TriggerKind::Boot, _) => "at startup".to_string(),
                (TriggerKind::Other, _) => continue,
            };
            if !parts.contains(&p) {
                parts.push(p);
            }
        }
        parts.join(", ")
    }
}

/// The element names from the root down to here.
fn at(stack: &[String], path: &[&str]) -> bool {
    stack.len() == path.len() && stack.iter().zip(path).all(|(a, b)| a == b)
}

fn ends(stack: &[String], tail: &[&str]) -> bool {
    stack.len() >= tail.len() && stack[stack.len() - tail.len()..].iter().zip(tail).all(|(a, b)| a == b)
}

/// Parse a task's XML. Err for anything that is not a well-formed Task document within the caps.
pub fn parse(xml: &str) -> Result<TaskDef, String> {
    if xml.len() > MAX_XML {
        return Err(format!("the task's XML is {} KB, more than VibeBoot reads ({} KB)", xml.len() / 1024, MAX_XML / 1024));
    }
    let mut r = quick_xml::Reader::from_str(xml);
    // Text is not trimmed here: an entity splits it ("Up &amp; Co" comes as three pieces), and
    // trimming each piece would eat the spaces around it. `close` trims the whole.
    r.config_mut().trim_text(false);
    let mut stack: Vec<String> = Vec::new();
    let mut text = String::new();
    let mut def = TaskDef::default();
    let mut root_seen = false;
    let mut context: Option<String> = None;
    // Principals by id: (id, user, run level).
    let mut principals: Vec<(Option<String>, Option<String>, Option<String>)> = Vec::new();
    // The action and trigger being read.
    let mut exec: Option<(String, String)> = None;
    let mut com: Option<String> = None;
    let mut trig: Option<Trigger> = None;
    loop {
        let ev = r.read_event().map_err(|e| format!("the task's XML is malformed ({e})"))?;
        match ev {
            Event::Start(ref e) | Event::Empty(ref e) => {
                let empty = matches!(ev, Event::Empty(_));
                let name = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                if stack.is_empty() {
                    if name != "Task" || root_seen {
                        return Err(format!("not a task (its root is <{name}>)"));
                    }
                    root_seen = true;
                }
                if stack.len() > 32 {
                    return Err("the task's XML is nested too deep".into());
                }
                let attr = |k: &str| e.try_get_attribute(k).ok().flatten().and_then(|a| a.normalized_value(XmlVersion::Implicit1_0).ok().map(|v| v.into_owned()));
                stack.push(name.clone());
                text.clear();
                if at(&stack, &["Task", "Actions"]) {
                    context = attr("Context");
                } else if at(&stack, &["Task", "Principals", "Principal"]) {
                    if principals.len() < MAX_ITEMS {
                        principals.push((attr("id"), None, None));
                    }
                } else if stack.len() == 3 && stack[1] == "Triggers" {
                    let kind = match name.as_str() {
                        "LogonTrigger" => TriggerKind::Logon,
                        "BootTrigger" => TriggerKind::Boot,
                        _ => TriggerKind::Other,
                    };
                    trig = Some(Trigger { kind, user: None, enabled: true });
                } else if stack.len() == 3 && stack[1] == "Actions" {
                    match name.as_str() {
                        "Exec" => exec = Some((String::new(), String::new())),
                        "ComHandler" => com = Some(String::new()),
                        other => {
                            if def.actions.len() < MAX_ITEMS {
                                def.actions.push(Action::Other(other.to_string()));
                            }
                        }
                    }
                }
                if empty {
                    close(&mut stack, &mut text, &mut def, &mut principals, &mut exec, &mut com, &mut trig);
                }
            }
            Event::End(_) => {
                if stack.is_empty() {
                    return Err("the task's XML is malformed (an end without a start)".into());
                }
                close(&mut stack, &mut text, &mut def, &mut principals, &mut exec, &mut com, &mut trig);
            }
            Event::Text(t) => {
                let s = t.decode().map_err(|e| format!("the task's XML is malformed ({e})"))?;
                push_text(&mut text, &s);
            }
            Event::CData(t) => {
                let s = t.decode().map_err(|e| format!("the task's XML is malformed ({e})"))?;
                push_text(&mut text, &s);
            }
            Event::GeneralRef(g) => {
                let c = match g.resolve_char_ref() {
                    Ok(Some(c)) => c,
                    _ => match g.as_ref() {
                        b"amp" => '&',
                        b"lt" => '<',
                        b"gt" => '>',
                        b"quot" => '"',
                        b"apos" => '\'',
                        other => return Err(format!("the task's XML names an unknown entity ({})", String::from_utf8_lossy(other))),
                    },
                };
                push_text(&mut text, c.encode_utf8(&mut [0; 4]));
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if !root_seen {
        return Err("the task's XML is empty".into());
    }
    if !stack.is_empty() {
        return Err("the task's XML ends early".into());
    }
    // The principal the actions run as: the one Actions' Context names, else the first.
    let p = principals.iter().find(|p| context.is_some() && p.0 == context).or(principals.first());
    if let Some((_, user, level)) = p {
        def.user = user.clone();
        def.run_level = level.clone();
    }
    Ok(def)
}

fn push_text(text: &mut String, s: &str) {
    if text.len() + s.len() <= MAX_TEXT {
        text.push_str(s);
    }
}

fn some(t: &str) -> Option<String> {
    let t = t.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// An element ends: what its text means where it stood.
fn close(stack: &mut Vec<String>, text: &mut String, def: &mut TaskDef, principals: &mut [(Option<String>, Option<String>, Option<String>)], exec: &mut Option<(String, String)>, com: &mut Option<String>, trig: &mut Option<Trigger>) {
    let t = std::mem::take(text);
    if at(stack, &["Task", "RegistrationInfo", "Date"]) {
        def.date = some(&t);
    } else if at(stack, &["Task", "RegistrationInfo", "Author"]) {
        def.author = some(&t);
    } else if at(stack, &["Task", "Settings", "Hidden"]) {
        def.hidden = t.trim().eq_ignore_ascii_case("true");
    } else if at(stack, &["Task", "Principals", "Principal", "UserId"]) {
        if let Some(p) = principals.last_mut() {
            p.1 = some(&t);
        }
    } else if at(stack, &["Task", "Principals", "Principal", "RunLevel"]) {
        if let Some(p) = principals.last_mut() {
            p.2 = some(&t);
        }
    } else if stack.len() == 4 && stack[1] == "Triggers" && stack[3] == "UserId" {
        if let Some(tr) = trig.as_mut() {
            tr.user = some(&t);
        }
    } else if stack.len() == 4 && stack[1] == "Triggers" && stack[3] == "Enabled" {
        if let Some(tr) = trig.as_mut() {
            tr.enabled = !t.trim().eq_ignore_ascii_case("false");
        }
    } else if ends(stack, &["Actions", "Exec", "Command"]) && stack.len() == 4 {
        if let Some(x) = exec.as_mut() {
            x.0 = t.trim().to_string();
        }
    } else if ends(stack, &["Actions", "Exec", "Arguments"]) && stack.len() == 4 {
        if let Some(x) = exec.as_mut() {
            x.1 = t.trim().to_string();
        }
    } else if ends(stack, &["Actions", "ComHandler", "ClassId"]) && stack.len() == 4 {
        if let Some(c) = com.as_mut() {
            *c = t.trim().to_string();
        }
    } else if stack.len() == 3 && stack[1] == "Triggers" {
        if let Some(tr) = trig.take()
            && def.triggers.len() < MAX_ITEMS {
                def.triggers.push(tr);
            }
    } else if stack.len() == 3 && stack[1] == "Actions" {
        if let Some((command, args)) = exec.take() {
            if def.actions.len() < MAX_ITEMS {
                def.actions.push(Action::Exec { command, args });
            }
        } else if let Some(clsid) = com.take()
            && def.actions.len() < MAX_ITEMS {
                def.actions.push(Action::ComHandler { clsid });
            }
    }
    stack.pop();
}
