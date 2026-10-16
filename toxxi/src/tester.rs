use std::sync::LazyLock;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[macro_export]
macro_rules! tlog {
    ($obj:expr, $($arg:tt)*) => {
        println!("[{:>6.3}s] {}", $obj.elapsed(), format_args!($($arg)*))
    };
}

use crate::app::{AppContext, TICK_RATE};
use crate::config::Config;
use crate::model::{DomainState, Model, WindowId};
use crate::msg::{AppCmd, Cmd, Msg, SystemEvent, ToxAction, ToxEvent};
use crate::update::{handle_enter, update};
use crate::worker;

use toxcore::tox::{Address, DhtId, FriendNumber, Options as ToxOptions, Tox, ToxConnection};
use toxcore::types::ToxLogLevel;

// Tests run at the same time, in one process and in several. Each process
// gets its own range, and hands out each port in it once.
const FIRST_PORT: u16 = 20000;
const PORTS_PER_PROCESS: u16 = 40;
const PROCESS_RANGES: u32 = 1000;
static NEXT_PORT: LazyLock<AtomicU16> = LazyLock::new(|| {
    let range = (std::process::id() % PROCESS_RANGES) as u16;
    AtomicU16::new(FIRST_PORT + range * PORTS_PER_PROCESS)
});

pub fn find_free_ports(count: usize) -> Vec<u16> {
    eprintln!("Finding {} free ports...", count);
    let mut ports = Vec::new();
    let mut toxes = Vec::new();
    while ports.len() < count {
        let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
        assert!(port < u16::MAX, "no free ports left");
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
    pub tox_id: Address,
    pub dht_id: DhtId,
    pub temp_dir: TempDir,
    pub start_time: Instant,
    pub should_quit: bool,
    last_tick: Instant,
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

        let initial_state = worker::get_initial_state(&savedata_path).unwrap();

        let mut domain = DomainState::new(
            initial_state.tox_id,
            initial_state.name.clone(),
            initial_state.status_message.clone(),
            initial_state.status_type,
        );

        let mut friend_map = std::collections::HashMap::new();
        for (fid, info) in initial_state.friends {
            if let Some(pk) = info.public_key {
                domain.friends.insert(pk, info);
                friend_map.insert(fid, pk);
            }
        }

        let mut model = Model::new(domain, config.clone(), config.clone());
        model.session.friend_numbers = friend_map;

        model.reconcile(vec![], initial_state.groups, initial_state.conferences);

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
            savedata_path,
            config_dir: temp_dir.path().to_path_buf(),
            quit_at: None,
            tx_io,
            screenshots_dir: temp_dir.path().join("screenshots"),
        };

        Self {
            id,
            port,
            model,
            ctx,
            rx_msg,
            tx_msg,
            tox_id: initial_state.tox_id,
            dht_id: initial_state.dht_id,
            temp_dir,
            start_time,
            should_quit: false,
            last_tick: start_time,
        }
    }

    pub async fn step(&mut self) -> bool {
        if self.last_tick.elapsed() >= TICK_RATE {
            self.last_tick = Instant::now();
            let _ = self.tx_msg.send(Msg::System(SystemEvent::Tick));
        }
        while let Ok(msg) = self.rx_msg.try_recv() {
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
                Msg::Tox(ToxEvent::DhtId(dht_id)) => {
                    tlog!(self, "[CLIENT {} DHT ID] {}", self.id, dht_id);
                    self.dht_id = *dht_id;
                }
                Msg::Tox(ToxEvent::GroupCreated(gnum, chat_id, name)) => {
                    tlog!(
                        self,
                        "[CLIENT {} GROUP CREATED] num={}, id={}, name={:?}",
                        self.id,
                        gnum.0,
                        chat_id,
                        name
                    )
                }
                Msg::Tox(ToxEvent::GroupTopic(gnum, topic, _)) => {
                    tlog!(
                        self,
                        "[CLIENT {} GROUP TOPIC] num={}, topic={}",
                        self.id,
                        gnum.0,
                        topic
                    )
                }
                Msg::Tox(ToxEvent::GroupInvite(f, data, name)) => {
                    tlog!(
                        self,
                        "[CLIENT {} GROUP INVITE] friend={}, data={}, name={}",
                        self.id,
                        f.0,
                        data,
                        name
                    )
                }
                Msg::Tox(ToxEvent::ConferenceInvite(f, kind, cookie)) => {
                    tlog!(
                        self,
                        "[CLIENT {} CONF INVITE] friend={}, kind={:?}, cookie={}",
                        self.id,
                        f.0,
                        kind,
                        cookie
                    )
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
                Msg::IO(crate::msg::IOEvent::FileFinished(_, file_id, _)) => {
                    tlog!(self, "[CLIENT {} IO FINISH] file={}", self.id, file_id)
                }
                _ => {}
            }

            if let Msg::Tox(ToxEvent::FriendRequest(pk, _)) = &msg {
                let _ = self
                    .ctx
                    .execute(
                        vec![Cmd::Tox(ToxAction::AcceptFriend(*pk))],
                        &mut self.model,
                    )
                    .await;
            }

            let cmds = update(&mut self.model, msg);
            if self.ctx.execute(cmds, &mut self.model).await.should_quit {
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

    pub fn set_active_window_by_id(&mut self, window_id: WindowId) {
        let index = self
            .model
            .ui
            .window_ids
            .iter()
            .position(|&id| id == window_id)
            .expect("Window ID not found in client's window list");
        self.set_active_window(index);
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
        let c0_port = self.clients[0].port;
        let dht_id = self.clients[0].dht_id;
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
                .send(ToxAction::Bootstrap(
                    "127.0.0.1".to_owned(),
                    c0_port,
                    dht_id,
                ))
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
