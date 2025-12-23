use std::sync::mpsc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::sync::broadcast;

#[macro_export]
macro_rules! tlog {
    ($obj:expr, $($arg:tt)*) => {
        println!("[{:>6.3}s] {}", $obj.elapsed(), format_args!($($arg)*))
    };
}

use crate::app::AppContext;
use crate::config::Config;
use crate::model::{DomainState, Model};
use crate::msg::{AppCmd, Cmd, Msg, SystemEvent, ToxAction, ToxEvent};
use crate::script::{ScriptController, ScriptRequest, ScriptResponse};
use crate::update::{handle_enter, update};
use crate::worker;

use toxcore::tox::{Address, FriendNumber, Options as ToxOptions, Tox, ToxConnection};
use toxcore::types::ToxLogLevel;

pub fn find_free_ports(count: usize) -> Vec<u16> {
    eprintln!("Finding {} free ports...", count);
    let mut ports = Vec::new();
    let mut port = 33445;
    let mut toxes = Vec::new();
    while ports.len() < count && port < 65535 {
        let mut opts = ToxOptions::new().unwrap();
        opts.set_start_port(port);
        opts.set_end_port(port);
        opts.set_udp_enabled(true);
        opts.set_local_discovery_enabled(false);
        opts.set_tcp_port(port);
        if let Ok(t) = Tox::new(opts) {
            ports.push(port);
            toxes.push(t);
        }
        port += 1;
    }
    eprintln!("Found ports: {:?}", ports);
    ports
}

pub struct TestClient {
    pub id: usize,
    pub port: u16,
    pub model: Model,
    pub ctx: AppContext,
    pub rx_msg: mpsc::Receiver<Msg>,
    pub tx_msg: mpsc::Sender<Msg>,
    pub event_tx: broadcast::Sender<Msg>,
    pub tox_id: Address,
    pub temp_dir: TempDir,
    pub script_ctrl: Option<ScriptController>,
    pub auto_accept_friends: bool,
    pub start_time: Instant,
    pub should_quit: bool,
}

impl TestClient {
    pub fn new(id: usize, port: u16, start_time: Instant) -> Self {
        let temp_dir = TempDir::new().unwrap();
        let savedata_path = Some(temp_dir.path().join("savedata.tox"));

        let config = Config {
            start_port: port,
            end_port: port,
            udp_enabled: true,
            ipv6_enabled: false,
            local_discovery_enabled: true,
            ..Default::default()
        };

        let (tox_id, self_pk, name, status, status_type, friends, groups, confs) =
            worker::get_initial_state(&savedata_path).unwrap();

        let mut domain =
            DomainState::new(tox_id, self_pk, name.clone(), status.clone(), status_type);

        let mut friend_map = std::collections::HashMap::new();
        for (fid, info) in friends {
            if let Some(pk) = info.public_key {
                domain.friends.insert(pk, info);
                friend_map.insert(fid, pk);
            }
        }

        let mut model = Model::new(domain, config.clone(), config.clone());
        model.session.friend_numbers = friend_map;

        model.reconcile(vec![], groups, confs);

        let (tx_msg, rx_msg) = mpsc::channel();
        let (tx_tox_action, rx_tox_action) = mpsc::channel();
        let (tx_io, rx_io) = mpsc::channel();

        let tox_handle = worker::spawn_tox(
            tx_msg.clone(),
            tx_io.clone(),
            rx_tox_action,
            savedata_path.clone(),
            &model.config,
            vec![],
            temp_dir.path().to_path_buf(),
        );

        let _io_handle = crate::io::spawn_io_worker(
            tx_msg.clone(),
            tx_tox_action.clone(),
            rx_io,
            temp_dir.path().to_path_buf(),
            temp_dir.path().join("downloads"),
        );

        let ctx = AppContext {
            tx_tox_action,
            tox_handle,
            nodes: vec![],
            savedata_path,
            config_dir: temp_dir.path().to_path_buf(),
            tx_msg: tx_msg.clone(),
            quit_at: None,
            tx_io,
            downloads_dir: temp_dir.path().join("downloads"),
            screenshots_dir: temp_dir.path().join("screenshots"),
        };

        let (event_tx, _) = broadcast::channel(1024);

        Self {
            id,
            port,
            model,
            ctx,
            rx_msg,
            tx_msg,
            event_tx,
            tox_id,
            temp_dir,
            script_ctrl: None,
            auto_accept_friends: true,
            start_time,
            should_quit: false,
        }
    }

    pub async fn step(&mut self) -> bool {
        while let Ok(msg) = self.rx_msg.try_recv() {
            // Broadcast the message to any observers (tests)
            let _ = self.event_tx.send(msg.clone());

            // Debug logging for tests
            match &msg {
                Msg::System(SystemEvent::Log {
                    severity,
                    context: _,
                    message,
                }) => {
                    tlog!(
                        self,
                        "[CLIENT {} LOG] [{:?}] {}",
                        self.id,
                        severity,
                        message
                    )
                }
                Msg::Tox(ToxEvent::Log(lvl, file, line, func, m)) => {
                    if *lvl != ToxLogLevel::TOX_LOG_LEVEL_TRACE {
                        tlog!(
                            self,
                            "[CLIENT {} TOX {:?}] {}:{}:{} - {}",
                            self.id,
                            lvl,
                            file,
                            line,
                            func,
                            m
                        );
                    }
                }
                Msg::Tox(ToxEvent::ConnectionStatus(s)) => {
                    tlog!(self, "[CLIENT {} CONN] {:?}", self.id, s)
                }
                Msg::Tox(ToxEvent::Address(addr)) => {
                    tlog!(self, "[CLIENT {} ID] {}", self.id, addr);
                    self.tox_id = *addr;
                }
                Msg::Tox(ToxEvent::FriendStatus(f, s, _)) => {
                    tlog!(self, "[CLIENT {} FRIEND {} STATUS] {:?}", self.id, f.0, s)
                }
                Msg::Tox(ToxEvent::FileRecv(f, fn_id, kind, size, filename)) => {
                    tlog!(
                        self,
                        "[CLIENT {} FILE RECV] friend={}, file={}, kind={}, size={}, name={}",
                        self.id,
                        f.0,
                        fn_id,
                        kind,
                        size,
                        filename
                    )
                }
                Msg::Tox(ToxEvent::FileRecvChunk(f, file_id, pos, data)) => {
                    tlog!(
                        self,
                        "[CLIENT {} CHUNK RECV] friend={}, file={}, pos={}, len={}",
                        self.id,
                        f.0,
                        file_id,
                        pos,
                        data.len()
                    )
                }
                Msg::Tox(ToxEvent::FileChunkRequest(f, file_id, pos, len)) => {
                    tlog!(
                        self,
                        "[CLIENT {} CHUNK REQ] friend={}, file={}, pos={}, len={}",
                        self.id,
                        f.0,
                        file_id,
                        pos,
                        len
                    )
                }
                Msg::Tox(ToxEvent::FileChunkSent(f, file_id, pos, len)) => {
                    tlog!(
                        self,
                        "[CLIENT {} CHUNK SENT] friend={}, file={}, pos={}, len={}",
                        self.id,
                        f.0,
                        file_id,
                        pos,
                        len
                    )
                }
                Msg::IO(crate::msg::IOEvent::FileStarted(_, file_id, path, size)) => {
                    tlog!(
                        self,
                        "[CLIENT {} IO START] file={}, path={}, size={}",
                        self.id,
                        file_id,
                        path,
                        size
                    )
                }
                Msg::IO(crate::msg::IOEvent::FileChunkRead(_, file_id, pos, len)) => {
                    tlog!(
                        self,
                        "[CLIENT {} IO READ] file={}, pos={}, len={}",
                        self.id,
                        file_id,
                        pos,
                        len
                    )
                }
                Msg::IO(crate::msg::IOEvent::FileChunkWritten(_, file_id, pos, len)) => {
                    tlog!(
                        self,
                        "[CLIENT {} IO WRITE] file={}, pos={}, len={}",
                        self.id,
                        file_id,
                        pos,
                        len
                    )
                }
                Msg::IO(crate::msg::IOEvent::FileError(_, file_id, err)) => {
                    tlog!(
                        self,
                        "[CLIENT {} IO ERROR] file={}, err={}",
                        self.id,
                        file_id,
                        err
                    )
                }
                Msg::IO(crate::msg::IOEvent::FileFinished(_, file_id)) => {
                    tlog!(self, "[CLIENT {} IO FINISH] file={}", self.id, file_id)
                }
                _ => {}
            }

            if self.auto_accept_friends
                && let Msg::Tox(ToxEvent::FriendRequest(pk, _)) = &msg
            {
                let _ = self
                    .ctx
                    .execute(
                        vec![Cmd::Tox(ToxAction::AcceptFriend(*pk))],
                        &mut self.model,
                    )
                    .await;
            }

            if let Some(ctrl) = &mut self.script_ctrl {
                if let Msg::System(SystemEvent::ScriptRequest(req)) = &msg {
                    ctrl.pending_req = Some(req.clone());
                    if let ScriptRequest::Command(cmd_str) = req {
                        let cmds = handle_enter(&mut self.model, cmd_str);
                        if self.ctx.execute(cmds, &mut self.model).await.should_quit {
                            self.should_quit = true;
                        }
                        ctrl.pending_req = None;
                        let _ = ctrl.tx_script_res.send(ScriptResponse::Ok);
                    }
                    continue;
                }
                ctrl.check_fulfillment(&self.model, &msg);
            }

            let cmds = update(&mut self.model, msg);
            if self.ctx.execute(cmds, &mut self.model).await.should_quit {
                self.should_quit = true;
            }
        }

        if let Some(ctrl) = &mut self.script_ctrl {
            ctrl.check_fulfillment(&self.model, &Msg::System(SystemEvent::Tick));
            if ctrl.is_finished() {
                self.should_quit = true;
            }
        }

        if self.should_quit {
            let _ = crate::model::save_state(&self.ctx.config_dir, &self.model);
            let _ = crate::config::save_config(&self.ctx.config_dir, &self.model.saved_config);
        }

        self.should_quit
    }

    pub async fn cmd(&mut self, command: &str) {
        let cmds = handle_enter(&mut self.model, command);
        if self.ctx.execute(cmds, &mut self.model).await.should_quit {
            self.should_quit = true;
        }
    }

    pub fn set_active_window(&mut self, index: usize) {
        self.model.set_active_window(index);
    }

    pub fn find_friend(&self, address: Address) -> Option<FriendNumber> {
        let pk = address.public_key();
        for (num, friend_pk) in &self.model.session.friend_numbers {
            if *friend_pk == pk {
                return Some(*num);
            }
        }
        None
    }

    pub fn elapsed(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64()
    }
}

pub struct TestHarness {
    pub clients: Vec<TestClient>,
    pub start_time: Instant,
}

impl TestHarness {
    pub fn new(count: usize) -> Self {
        eprintln!("Creating TestHarness with {} clients", count);
        let start_time = Instant::now();
        let ports = find_free_ports(count);
        let mut clients = Vec::new();
        for (i, &port) in ports.iter().enumerate().take(count) {
            clients.push(TestClient::new(i, port, start_time));
        }
        Self {
            clients,
            start_time,
        }
    }

    pub async fn link_all(&mut self) {
        eprintln!("Linking all clients...");
        // 0. Wait for all clients to have their real IDs
        tlog!(self, "Waiting for all clients to have their real IDs...");
        let start_ids: Vec<_> = self.clients.iter().map(|c| c.tox_id).collect();
        self.wait_for(
            |clients| {
                clients
                    .iter()
                    .enumerate()
                    .all(|(i, c)| c.tox_id != start_ids[i])
            },
            Duration::from_secs(5),
        )
        .await
        .expect("Clients failed to get real IDs");
        eprintln!("All clients got real IDs");

        // 1. Bootstrap all to Client 0
        tlog!(self, "Linking {} clients...", self.clients.len());
        let c0_id = self.clients[0].tox_id;
        let c0_port = self.clients[0].port;
        let pk = c0_id.public_key();
        for i in 1..self.clients.len() {
            tlog!(
                self,
                "Client {} bootstrapping to Client 0 at 127.0.0.1:{}",
                i,
                c0_port
            );
            self.clients[i]
                .ctx
                .tx_tox_action
                .send(ToxAction::Bootstrap("127.0.0.1".to_owned(), c0_port, pk))
                .unwrap();
        }

        // 2. Wait for DHT online
        tlog!(self, "Waiting for DHT online status...");
        self.wait_for(
            |clients| {
                clients.iter().all(|c| {
                    c.model.domain.self_connection_status != ToxConnection::TOX_CONNECTION_NONE
                })
            },
            Duration::from_secs(30),
        )
        .await
        .expect("Clients failed to go online");
        tlog!(self, "DHT online.");

        // 3. Bidirectional friendship Alice <-> Bob, Alice <-> Charlie, Bob <-> Charlie
        tlog!(self, "Establishing friendships...");
        for i in 0..self.clients.len() {
            for j in (i + 1)..self.clients.len() {
                let friend_id = self.clients[j].tox_id;
                tlog!(self, "Client {} adding Client {} ({})", i, j, friend_id);
                self.clients[i]
                    .ctx
                    .tx_tox_action
                    .send(ToxAction::AddFriend(
                        friend_id.to_string(),
                        "Test".to_owned(),
                    ))
                    .unwrap();
            }
        }

        // 4. Wait for all to see each other online
        let total_friends = self.clients.len() - 1;
        tlog!(
            self,
            "Waiting for {} friends to be online for each client...",
            total_friends
        );
        self.wait_for(
            |clients| {
                clients.iter().all(|c| {
                    let count = c
                        .model
                        .domain
                        .friends
                        .values()
                        .filter(|f| f.connection != ToxConnection::TOX_CONNECTION_NONE)
                        .count();
                    count == total_friends
                })
            },
            Duration::from_secs(30),
        )
        .await
        .expect("Friendships failed to connect online");
        tlog!(self, "All friends connected.");
    }

    pub async fn wait_for(
        &mut self,
        mut condition: impl FnMut(&[TestClient]) -> bool,
        timeout: Duration,
    ) -> Result<(), String> {
        let start = Instant::now();
        while start.elapsed() < timeout {
            for client in &mut self.clients {
                client.step().await;
            }
            if condition(&self.clients) {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Err("Timeout waiting for condition".to_owned())
    }

    pub async fn run_step(&mut self) {
        for client in &mut self.clients {
            client.step().await;
        }
    }

    pub async fn shutdown(&mut self) {
        for client in &mut self.clients {
            client
                .ctx
                .execute(vec![Cmd::App(AppCmd::Quit)], &mut client.model)
                .await;
        }
    }

    pub fn elapsed(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64()
    }
}
