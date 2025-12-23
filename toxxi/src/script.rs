use crate::commands;
use crate::model::Model;
use crate::msg::{Msg, SystemEvent, ToxEvent};
use crate::waits;
use rhai::{Engine, EvalAltResult, Position, Scope};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub enum ScriptRequest {
    Command(String),
    WaitOnline,
    WaitFriendOnline(u32),
    WaitReadReceipt(u32),
    WaitFriendMessage(u32, String),
    WaitFileRecv(u32),
    Sleep(u64),
}

#[derive(Debug)]
pub enum ScriptResponse {
    Ok,
    FileId(String),
}

pub struct ScriptChannels {
    pub req_tx: mpsc::Sender<Msg>,
    pub res_rx: Mutex<mpsc::Receiver<ScriptResponse>>,
}

pub fn spawn_script(
    path: PathBuf,
    tx: mpsc::Sender<Msg>,
) -> (
    thread::JoinHandle<Result<(), Box<EvalAltResult>>>,
    mpsc::Sender<ScriptResponse>,
) {
    let (res_tx, res_rx) = mpsc::channel();

    let channels = Arc::new(ScriptChannels {
        req_tx: tx,
        res_rx: Mutex::new(res_rx),
    });

    let handle = thread::spawn(move || {
        let mut engine = Engine::new();

        let c = channels.clone();
        engine.register_fn("cmd", move |s: String| -> Result<(), Box<EvalAltResult>> {
            c.req_tx
                .send(Msg::System(SystemEvent::ScriptRequest(
                    ScriptRequest::Command(s),
                )))
                .map_err(|e| {
                    Box::new(EvalAltResult::ErrorRuntime(
                        format!("Send error: {}", e).into(),
                        Position::NONE,
                    ))
                })?;
            c.res_rx.lock().unwrap().recv().map_err(|e| {
                Box::new(EvalAltResult::ErrorRuntime(
                    format!("Recv error: {}", e).into(),
                    Position::NONE,
                ))
            })?;
            Ok(())
        });

        let c = channels.clone();
        engine.register_fn("wait_online", move || -> Result<(), Box<EvalAltResult>> {
            c.req_tx
                .send(Msg::System(SystemEvent::ScriptRequest(
                    ScriptRequest::WaitOnline,
                )))
                .map_err(|e| {
                    Box::new(EvalAltResult::ErrorRuntime(
                        format!("Send error: {}", e).into(),
                        Position::NONE,
                    ))
                })?;
            c.res_rx.lock().unwrap().recv().map_err(|e| {
                Box::new(EvalAltResult::ErrorRuntime(
                    format!("Recv error: {}", e).into(),
                    Position::NONE,
                ))
            })?;
            Ok(())
        });

        let c = channels.clone();
        engine.register_fn(
            "wait_friend_online",
            move |id: i64| -> Result<(), Box<EvalAltResult>> {
                c.req_tx
                    .send(Msg::System(SystemEvent::ScriptRequest(
                        ScriptRequest::WaitFriendOnline(id as u32),
                    )))
                    .map_err(|e| {
                        Box::new(EvalAltResult::ErrorRuntime(
                            format!("Send error: {}", e).into(),
                            Position::NONE,
                        ))
                    })?;
                c.res_rx.lock().unwrap().recv().map_err(|e| {
                    Box::new(EvalAltResult::ErrorRuntime(
                        format!("Recv error: {}", e).into(),
                        Position::NONE,
                    ))
                })?;
                Ok(())
            },
        );

        let c = channels.clone();
        engine.register_fn(
            "wait_friend_msg",
            move |id: i64, sub: String| -> Result<(), Box<EvalAltResult>> {
                c.req_tx
                    .send(Msg::System(SystemEvent::ScriptRequest(
                        ScriptRequest::WaitFriendMessage(id as u32, sub),
                    )))
                    .map_err(|e| {
                        Box::new(EvalAltResult::ErrorRuntime(
                            format!("Send error: {}", e).into(),
                            Position::NONE,
                        ))
                    })?;
                c.res_rx.lock().unwrap().recv().map_err(|e| {
                    Box::new(EvalAltResult::ErrorRuntime(
                        format!("Recv error: {}", e).into(),
                        Position::NONE,
                    ))
                })?;
                Ok(())
            },
        );

        let c = channels.clone();
        engine.register_fn(
            "wait_read_receipt",
            move |id: i64| -> Result<(), Box<EvalAltResult>> {
                c.req_tx
                    .send(Msg::System(SystemEvent::ScriptRequest(
                        ScriptRequest::WaitReadReceipt(id as u32),
                    )))
                    .map_err(|e| {
                        Box::new(EvalAltResult::ErrorRuntime(
                            format!("Send error: {}", e).into(),
                            Position::NONE,
                        ))
                    })?;
                c.res_rx.lock().unwrap().recv().map_err(|e| {
                    Box::new(EvalAltResult::ErrorRuntime(
                        format!("Recv error: {}", e).into(),
                        Position::NONE,
                    ))
                })?;
                Ok(())
            },
        );

        let c = channels.clone();
        engine.register_fn("sleep", move |ms: i64| -> Result<(), Box<EvalAltResult>> {
            c.req_tx
                .send(Msg::System(SystemEvent::ScriptRequest(
                    ScriptRequest::Sleep(ms as u64),
                )))
                .map_err(|e| {
                    Box::new(EvalAltResult::ErrorRuntime(
                        format!("Send error: {}", e).into(),
                        Position::NONE,
                    ))
                })?;
            c.res_rx.lock().unwrap().recv().map_err(|e| {
                Box::new(EvalAltResult::ErrorRuntime(
                    format!("Recv error: {}", e).into(),
                    Position::NONE,
                ))
            })?;
            Ok(())
        });

        let c = channels.clone();
        engine.register_fn(
            "timeout",
            move |ms: i64| -> Result<(), Box<EvalAltResult>> {
                c.req_tx
                    .send(Msg::System(SystemEvent::ScriptRequest(
                        ScriptRequest::Command(format!("/timeout {}", ms)),
                    )))
                    .map_err(|e| {
                        Box::new(EvalAltResult::ErrorRuntime(
                            format!("Send error: {}", e).into(),
                            Position::NONE,
                        ))
                    })?;
                c.res_rx.lock().unwrap().recv().map_err(|e| {
                    Box::new(EvalAltResult::ErrorRuntime(
                        format!("Recv error: {}", e).into(),
                        Position::NONE,
                    ))
                })?;
                Ok(())
            },
        );

        let c = channels.clone();
        engine.register_fn(
            "wait_file_recv",
            move |id: i64| -> Result<String, Box<EvalAltResult>> {
                c.req_tx
                    .send(Msg::System(SystemEvent::ScriptRequest(
                        ScriptRequest::WaitFileRecv(id as u32),
                    )))
                    .map_err(|e| {
                        Box::new(EvalAltResult::ErrorRuntime(
                            format!("Send error: {}", e).into(),
                            Position::NONE,
                        ))
                    })?;
                let res = c.res_rx.lock().unwrap().recv().map_err(|e| {
                    Box::new(EvalAltResult::ErrorRuntime(
                        format!("Recv error: {}", e).into(),
                        Position::NONE,
                    ))
                })?;
                match res {
                    ScriptResponse::FileId(fid) => Ok(fid),
                    _ => Ok(String::new()),
                }
            },
        );

        // Dynamically register all commands from the registry
        for cmd_def in commands::COMMANDS.iter() {
            let c = channels.clone();
            let name = cmd_def.name;
            engine.register_fn(
                name,
                move |args: String| -> Result<(), Box<EvalAltResult>> {
                    c.req_tx
                        .send(Msg::System(SystemEvent::ScriptRequest(
                            ScriptRequest::Command(format!("/{} {}", name, args)),
                        )))
                        .map_err(|e| {
                            Box::new(EvalAltResult::ErrorRuntime(
                                format!("Send error: {}", e).into(),
                                Position::NONE,
                            ))
                        })?;
                    c.res_rx.lock().unwrap().recv().map_err(|e| {
                        Box::new(EvalAltResult::ErrorRuntime(
                            format!("Recv error: {}", e).into(),
                            Position::NONE,
                        ))
                    })?;
                    Ok(())
                },
            );

            // Also register a version with no args if useful
            let c = channels.clone();
            engine.register_fn(name, move || -> Result<(), Box<EvalAltResult>> {
                c.req_tx
                    .send(Msg::System(SystemEvent::ScriptRequest(
                        ScriptRequest::Command(format!("/{}", name)),
                    )))
                    .map_err(|e| {
                        Box::new(EvalAltResult::ErrorRuntime(
                            format!("Send error: {}", e).into(),
                            Position::NONE,
                        ))
                    })?;
                c.res_rx.lock().unwrap().recv().map_err(|e| {
                    Box::new(EvalAltResult::ErrorRuntime(
                        format!("Recv error: {}", e).into(),
                        Position::NONE,
                    ))
                })?;
                Ok(())
            });
        }

        let mut scope = Scope::new();
        engine.run_file_with_scope(&mut scope, path)
    });

    (handle, res_tx)
}

pub struct ScriptController {
    pub pending_req: Option<ScriptRequest>,
    pub sleep_until: Option<Instant>,
    pub tx_script_res: mpsc::Sender<ScriptResponse>,
    pub script_handle: thread::JoinHandle<Result<(), Box<EvalAltResult>>>,
}

impl ScriptController {
    pub fn new(path: PathBuf, tx_msg: mpsc::Sender<Msg>) -> Self {
        let (script_handle, tx_script_res) = spawn_script(path, tx_msg);
        Self {
            pending_req: None,
            sleep_until: None,
            tx_script_res,
            script_handle,
        }
    }

    pub fn is_finished(&self) -> bool {
        self.script_handle.is_finished()
    }

    pub fn check_fulfillment(&mut self, model: &Model, msg: &Msg) -> bool {
        let mut fulfilled = false;
        if let Some(req) = &self.pending_req {
            // 1. Registry-based fulfillment
            for w in waits::WAITS {
                let req_name = match req {
                    ScriptRequest::WaitOnline => "WaitOnline",
                    ScriptRequest::WaitFriendOnline(_) => "WaitFriendOnline",
                    ScriptRequest::WaitReadReceipt(_) => "WaitReadReceipt",
                    ScriptRequest::WaitFriendMessage(_, _) => "WaitFriendMessage",
                    ScriptRequest::WaitFileRecv(_) => "WaitFileRecv",
                    _ => "",
                };

                if w.name == req_name && (w.is_fulfilled)(model, msg, Some(req)) {
                    fulfilled = true;
                    break;
                }
            }

            // 2. Specialized fulfillment (Sleep)
            if !fulfilled && let ScriptRequest::Sleep(ms) = req {
                if self.sleep_until.is_none() {
                    self.sleep_until = Some(Instant::now() + Duration::from_millis(*ms));
                }
                if let Some(until) = self.sleep_until
                    && Instant::now() >= until
                {
                    fulfilled = true;
                    self.sleep_until = None;
                }
            }
        }

        if fulfilled {
            let res = if let (
                Msg::Tox(ToxEvent::FileRecv(_, file, _, _, _)),
                Some(ScriptRequest::WaitFileRecv(_)),
            ) = (msg, &self.pending_req)
            {
                ScriptResponse::FileId(file.to_string())
            } else {
                ScriptResponse::Ok
            };
            self.pending_req = None;
            let _ = self.tx_script_res.send(res);
        }
        fulfilled
    }
}
