//! toxxi in an Android app: it runs on its own thread in the app's process
//! and draws on a [`screen`] the app's view shows. The functions here are
//! the native methods of `chat.tox.toxxi.Toxxi`.
#![deny(
    clippy::allow_attributes,
    clippy::allow_attributes_without_reason,
    clippy::let_underscore_must_use,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::wildcard_enum_match_arm
)]

mod screen;

use std::collections::HashMap;
use std::ffi::{CString, c_char, c_int};
use std::path::PathBuf;
use std::sync::mpsc::{self, Sender};
use std::sync::{LazyLock, Mutex, OnceLock};
use std::thread;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use jni::objects::{GlobalRef, JClass, JIntArray, JObject, JString, JValue};
use jni::sys::{jboolean, jint, jstring};
use jni::{JNIEnv, JavaVM};
use ratatui::Terminal;
use ratatui::layout::Size;
use toxxi::app::{self, Dirs};
use toxxi::config::{self, Config};
use toxxi::model::{InternalMessageId, Message, MessageContent, Model, UiMode, WindowId};
use toxxi::msg::{Msg, SystemEvent};
use toxxi::utils::Tell;

use screen::{LOOK_INTS, ScreenBackend};

/// The Java side, to call back.
struct Java {
    vm: JavaVM,
    class: GlobalRef,
}

static JAVA: OnceLock<Java> = OnceLock::new();

/// The chats notifications were about, by the name the app knows them by.
static CHATS: LazyLock<Mutex<HashMap<String, WindowId>>> = LazyLock::new(Mutex::default);

/// Where the app's input goes while toxxi runs.
static INPUT: Mutex<Option<Sender<Msg>>> = Mutex::new(None);

fn log(text: &str) {
    #[cfg(target_os = "android")]
    {
        unsafe extern "C" {
            fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
        }
        const ERROR: c_int = 6;
        let text = CString::new(text.replace('\0', " ")).unwrap_or_default();
        unsafe { __android_log_write(ERROR, c"toxxi".as_ptr(), text.as_ptr()) };
    }
    #[cfg(not(target_os = "android"))]
    eprintln!("{text}");
}

/// Runs `f` with the `Toxxi` class on this thread. Its local references
/// are freed after: toxxi's thread never returns to Java, which would free
/// them.
fn with_java(f: impl FnOnce(&mut JNIEnv, &JClass) -> jni::errors::Result<()>) {
    let Some(java) = JAVA.get() else {
        return;
    };
    let Ok(mut env) = java.vm.attach_current_thread_permanently() else {
        return;
    };
    let class = <&JClass>::from(java.class.as_obj());
    let result = env.with_local_frame(8, |env| f(env, class));
    if result.is_err() && env.exception_check().unwrap_or(false) {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "printing and clearing the exception is all there is to do"
        )]
        let _ = env.exception_describe();
        #[expect(
            clippy::let_underscore_must_use,
            reason = "printing and clearing the exception is all there is to do"
        )]
        let _ = env.exception_clear();
    }
}

/// Calls a static `void` method of `Toxxi` without arguments.
fn call_java(method: &str) {
    with_java(|env, class| env.call_static_method(class, method, "()V", &[]).map(drop));
}

fn send(msg: Msg) {
    if let Some(input) = INPUT.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
        input.tell(msg);
    }
}

fn string(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s).map(String::from).unwrap_or_default()
}

/// Starts toxxi once per process, with its files in `files`. Later calls
/// return false and do nothing.
#[unsafe(no_mangle)]
pub extern "system" fn Java_chat_tox_toxxi_Toxxi_start(
    mut env: JNIEnv,
    class: JClass,
    files: JString,
    downloads: JString,
    pictures: JString,
    rows: jint,
    cols: jint,
) -> jboolean {
    let (Ok(vm), Ok(class)) = (env.get_java_vm(), env.new_global_ref(class)) else {
        return 0;
    };
    if JAVA.set(Java { vm, class }).is_err() {
        return 0;
    }
    std::panic::set_hook(Box::new(|info| log(&info.to_string())));

    let files = PathBuf::from(string(&mut env, &files));
    let dirs = Dirs {
        savedata: Some(files.join("savedata.tox")),
        config: files.clone(),
        downloads: PathBuf::from(string(&mut env, &downloads)),
        screenshots: PathBuf::from(string(&mut env, &pictures)),
    };
    // toxxi shows paths under the home directory with ~.
    // SAFETY: no thread of ours reads the environment yet.
    unsafe { std::env::set_var("HOME", &files) };

    resize(rows, cols);
    let (tx, rx) = mpsc::channel();
    *INPUT.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx.clone());
    thread::Builder::new()
        .name("toxxi".to_owned())
        .spawn(move || run(dirs, tx, rx))
        .is_ok()
        .into()
}

fn run(dirs: Dirs, tx: Sender<Msg>, rx: mpsc::Receiver<Msg>) {
    // Phones save battery on UDP: a new profile starts with TCP only.
    if !dirs.config.join("config.json").exists() {
        let config = Config {
            udp_enabled: false,
            ..Config::default()
        };
        if let Err(e) = config::save_config(&dirs.config, &config) {
            log(&format!("can't write config.json: {e}"));
        }
    }

    let result = tokio::runtime::Runtime::new()
        .map_err(Box::from)
        .and_then(|runtime| {
            runtime.block_on(async {
                let mut terminal = Terminal::new(ScreenBackend {
                    flushed: || call_java("onScreenChanged"),
                })?;
                let mut notifier = Notifier::default();
                let mut writing = None;
                app::run(
                    &mut terminal,
                    dirs,
                    |_| {},
                    (tx, rx),
                    |model| {
                        notifier.notify(model);
                        let now = writes_message(model);
                        if writing.replace(now) != Some(now) {
                            with_java(|env, class| {
                                env.call_static_method(class, "onWriting", "(Z)V", &[now.into()])
                                    .map(drop)
                            });
                        }
                    },
                )
                .await
            })
        });
    if let Err(e) = result {
        log(&format!("toxxi stopped: {e}"));
    }
    *INPUT.lock().unwrap_or_else(|e| e.into_inner()) = None;
    call_java("onExit");
}

/// Whether what the user types is a chat message, which the keyboard may
/// correct, rather than a command, a chat's name or a key to type exactly.
fn writes_message(model: &Model) -> bool {
    let ui = &model.ui;
    matches!(
        model.active_window_id(),
        WindowId::Friend(_) | WindowId::Group(_) | WindowId::Conference(_)
    ) && ui.ui_mode == UiMode::Chat
        && ui.quick_switcher.is_none()
        && ui.command_menu.is_none()
        && ui.emoji_picker.is_none()
        && !ui.completion.active
        && !ui.input_state.text.starts_with('/')
}

/// Tells the app about new messages for the account: in chats with friends,
/// and those mentioning the account in groups.
#[derive(Default)]
struct Notifier {
    /// Messages from here on are new.
    next: Option<InternalMessageId>,
}

impl Notifier {
    fn notify(&mut self, model: &Model) {
        let next = model.domain.next_internal_id;
        let Some(from) = self.next.replace(next) else {
            // The first look: everything is old.
            return;
        };
        for (&window, conversation) in &model.domain.conversations {
            let new: Vec<&Message> = conversation
                .messages
                .iter()
                .rev()
                .take_while(|m| m.internal_id >= from)
                .filter(|m| {
                    !m.is_self
                        && !m.is_system()
                        && (matches!(window, WindowId::Friend(_)) || m.highlighted)
                })
                .collect();
            for message in new.into_iter().rev() {
                self.show(model, window, message);
            }
        }
    }

    fn show(&self, model: &Model, window: WindowId, message: &Message) {
        let text = match &message.content {
            MessageContent::Text(text) => text.clone(),
            MessageContent::List(items) => items.join("\n"),
            MessageContent::FileTransfer { name, .. } => format!("File: {name}"),
        };
        let title = model.window_name(window);
        let title = match window {
            WindowId::Friend(_) => title,
            _ => format!("{} in {title}", message.sender),
        };
        let chat = format!("{window:?}");
        CHATS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(chat.clone(), window);
        with_java(|env, class| {
            let chat = JObject::from(env.new_string(chat)?);
            let title = JObject::from(env.new_string(title)?);
            let text = JObject::from(env.new_string(text)?);
            env.call_static_method(
                class,
                "onMessage",
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                &[
                    JValue::Object(&chat),
                    JValue::Object(&title),
                    JValue::Object(&text),
                ],
            )
            .map(drop)
        });
    }
}

fn resize(rows: jint, cols: jint) -> Size {
    let clamp = |n: jint| n.clamp(1, jint::from(u16::MAX)) as u16;
    let size = Size::new(clamp(cols), clamp(rows));
    screen::resize(size);
    size
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_chat_tox_toxxi_Toxxi_resize(
    _env: JNIEnv,
    _class: JClass,
    rows: jint,
    cols: jint,
) {
    let size = resize(rows, cols);
    // Anything toxxi reads makes it draw again, at the new size.
    send(Msg::Input(Event::Resize(size.width, size.height)));
}

/// The key for `code`: a character if it's 0 or more, else one of the keys
/// in Toxxi.kt.
fn key_code(code: jint) -> Option<KeyCode> {
    Some(match code {
        0.. => KeyCode::Char(char::from_u32(code as u32)?),
        -1 => KeyCode::Enter,
        -2 => KeyCode::Backspace,
        -3 => KeyCode::Delete,
        -4 => KeyCode::Tab,
        -5 => KeyCode::BackTab,
        -6 => KeyCode::Esc,
        -7 => KeyCode::Up,
        -8 => KeyCode::Down,
        -9 => KeyCode::Left,
        -10 => KeyCode::Right,
        -11 => KeyCode::Home,
        -12 => KeyCode::End,
        -13 => KeyCode::PageUp,
        -14 => KeyCode::PageDown,
        -15 => KeyCode::Insert,
        -32..=-21 => KeyCode::F((-20 - code) as u8),
        _ => return None,
    })
}

/// Presses a key. `modifiers` are crossterm's: Shift 1, Ctrl 2, Alt 4.
#[unsafe(no_mangle)]
pub extern "system" fn Java_chat_tox_toxxi_Toxxi_key(
    _env: JNIEnv,
    _class: JClass,
    code: jint,
    modifiers: jint,
) {
    if let Some(code) = key_code(code) {
        let modifiers = KeyModifiers::from_bits_truncate(modifiers as u8);
        send(Msg::Input(Event::Key(KeyEvent::new(code, modifiers))));
    }
}

/// Scrolls the chat `lines` down, or up if `lines` is negative, as a mouse
/// wheel does.
#[unsafe(no_mangle)]
pub extern "system" fn Java_chat_tox_toxxi_Toxxi_scroll(_env: JNIEnv, _class: JClass, lines: jint) {
    let kind = if lines < 0 {
        MouseEventKind::ScrollUp
    } else {
        MouseEventKind::ScrollDown
    };
    for _ in 0..lines.unsigned_abs() {
        send(Msg::Input(Event::Mouse(MouseEvent {
            kind,
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        })));
    }
}

/// Shows a chat a notification was about.
#[unsafe(no_mangle)]
pub extern "system" fn Java_chat_tox_toxxi_Toxxi_show(
    mut env: JNIEnv,
    _class: JClass,
    chat: JString,
) {
    let chat = string(&mut env, &chat);
    let window = CHATS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&chat)
        .copied();
    if let Some(window) = window {
        send(Msg::System(SystemEvent::Show(window)));
    }
}

/// Asks toxxi to save everything now: Android may end the app without warning.
#[unsafe(no_mangle)]
pub extern "system" fn Java_chat_tox_toxxi_Toxxi_save(_env: JNIEnv, _class: JClass) {
    send(Msg::System(SystemEvent::Save));
}

/// Copies the screen as a `rows` × `cols` grid: looks into `looks`
/// (LOOK_INTS per cell), and where each cell's text starts in the returned
/// string into `starts`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_chat_tox_toxxi_Toxxi_snapshot(
    env: JNIEnv,
    _class: JClass,
    rows: jint,
    cols: jint,
    looks: JIntArray,
    starts: JIntArray,
) -> jstring {
    let (Ok(rows), Ok(cols)) = (u16::try_from(rows), u16::try_from(cols)) else {
        return std::ptr::null_mut();
    };
    let cells = usize::from(rows) * usize::from(cols);
    let mut look_buf = Vec::with_capacity(cells * LOOK_INTS);
    let mut start_buf = Vec::with_capacity(cells + 1);
    let text = screen::snapshot(rows, cols, &mut look_buf, &mut start_buf);
    if env.set_int_array_region(&looks, 0, &look_buf).is_err()
        || env.set_int_array_region(&starts, 0, &start_buf).is_err()
    {
        return std::ptr::null_mut();
    }
    env.new_string(text)
        .map_or(std::ptr::null_mut(), JString::into_raw)
}
