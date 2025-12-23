use ratatui::{Terminal, backend::TestBackend};
use std::fs;
use toxcore::tox::{Address, PublicKey, ToxUserStatus};
use toxcore::types::ToxLogLevel;
use toxxi::config::Config;
use toxxi::model::{DomainState, Model, WindowId};
use toxxi::ui::draw;

fn create_test_model() -> Model {
    let config = Config::default();
    let domain = DomainState::new(
        Address([0u8; 38]),
        PublicKey([0u8; 32]),
        "Tester".to_string(),
        "I am a test".to_string(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    Model::new(domain, config.clone(), config)
}

#[test]
fn test_add_tox_log() {
    let mut model = create_test_model();

    model.add_tox_log(
        ToxLogLevel::TOX_LOG_LEVEL_INFO,
        "test.c".to_string(),
        123,
        "test_func".to_string(),
        "Test log message".to_string(),
    );

    assert_eq!(
        model
            .domain
            .tox_logs
            .get(&ToxLogLevel::TOX_LOG_LEVEL_INFO)
            .unwrap()
            .len(),
        1
    );
    let all_logs = model.all_tox_logs();
    assert_eq!(all_logs.len(), 1);
    let log = &all_logs[0];
    assert_eq!(log.level, ToxLogLevel::TOX_LOG_LEVEL_INFO);
    assert_eq!(log.file, "test.c");
    assert_eq!(log.line, 123);
    assert_eq!(log.func, "test_func");
    assert_eq!(log.message, "Test log message");
}

#[test]
fn test_tox_log_circular_buffer() {
    let mut model = create_test_model();

    for i in 0..1100 {
        model.add_tox_log(
            ToxLogLevel::TOX_LOG_LEVEL_DEBUG,
            "file.c".to_string(),
            i as u32,
            "func".to_string(),
            format!("message {}", i),
        );
    }

    let all_logs = model.all_tox_logs();
    assert_eq!(all_logs.len(), 200);
    assert_eq!(all_logs[0].line, 900);
    assert_eq!(all_logs[199].line, 1099);
}

#[test]
fn test_tox_log_per_level_buckets() {
    let mut model = create_test_model();

    // Fill INFO bucket
    for i in 0..300 {
        model.add_tox_log(
            ToxLogLevel::TOX_LOG_LEVEL_INFO,
            "info.c".to_string(),
            i,
            "func".to_string(),
            "info".to_string(),
        );
    }

    // Add one ERROR
    model.add_tox_log(
        ToxLogLevel::TOX_LOG_LEVEL_ERROR,
        "error.c".to_string(),
        1,
        "func".to_string(),
        "error".to_string(),
    );

    let all_logs = model.all_tox_logs();
    assert_eq!(all_logs.len(), 201); // 200 INFO + 1 ERROR
    assert!(
        all_logs
            .iter()
            .any(|l| l.level == ToxLogLevel::TOX_LOG_LEVEL_ERROR)
    );
}

#[test]
fn test_tox_log_filters() {
    let mut model = create_test_model();

    model.add_tox_log(
        ToxLogLevel::TOX_LOG_LEVEL_INFO,
        "file1.c".to_string(),
        1,
        "f1".to_string(),
        "msg1".to_string(),
    );
    model.add_tox_log(
        ToxLogLevel::TOX_LOG_LEVEL_ERROR,
        "file2.c".to_string(),
        2,
        "f2".to_string(),
        "msg2".to_string(),
    );
    model.add_tox_log(
        ToxLogLevel::TOX_LOG_LEVEL_DEBUG,
        "file1.c".to_string(),
        3,
        "f3".to_string(),
        "other".to_string(),
    );

    assert_eq!(model.all_tox_logs().len(), 3);

    // Filter by level
    model.ui.log_filters.levels = vec![ToxLogLevel::TOX_LOG_LEVEL_ERROR];
    assert_eq!(model.all_tox_logs().len(), 1);
    assert_eq!(
        model.all_tox_logs()[0].level,
        ToxLogLevel::TOX_LOG_LEVEL_ERROR
    );

    // Filter by file
    model.ui.log_filters = toxxi::model::LogFilters::default();
    model.ui.log_filters.file_pattern = Some("file1".to_string());
    assert_eq!(model.all_tox_logs().len(), 2);

    // Filter by msg
    model.ui.log_filters = toxxi::model::LogFilters::default();
    model.ui.log_filters.msg_pattern = Some("msg".to_string());
    assert_eq!(model.all_tox_logs().len(), 2);

    // Combined
    model.ui.log_filters.file_pattern = Some("file2".to_string());
    assert_eq!(model.all_tox_logs().len(), 1);
    assert_eq!(model.all_tox_logs()[0].file, "file2.c");
}

#[test]
fn test_tox_log_incremental_filters() {
    let mut model = create_test_model();
    model.add_tox_log(
        ToxLogLevel::TOX_LOG_LEVEL_INFO,
        "file.c".to_string(),
        1,
        "f".to_string(),
        "msg".to_string(),
    );
    model.add_tox_log(
        ToxLogLevel::TOX_LOG_LEVEL_TRACE,
        "file.c".to_string(),
        2,
        "f".to_string(),
        "msg".to_string(),
    );

    // Initially 2 logs
    assert_eq!(model.all_tox_logs().len(), 2);

    // Remove trace
    toxxi::update::handle_command(&mut model, "/logs level=-trace");
    assert_eq!(model.all_tox_logs().len(), 1);
    assert_eq!(
        model.all_tox_logs()[0].level,
        ToxLogLevel::TOX_LOG_LEVEL_INFO
    );

    // Add trace back
    toxxi::update::handle_command(&mut model, "/logs level=+trace");
    assert_eq!(model.all_tox_logs().len(), 2);

    // Set to only error (which doesn't exist)
    toxxi::update::handle_command(&mut model, "/logs level=error");
    assert_eq!(model.all_tox_logs().len(), 0);

    // Clear level filter
    toxxi::update::handle_command(&mut model, "/logs level=");
    assert_eq!(model.all_tox_logs().len(), 2);
}

#[test]
fn test_tox_log_scrolling() {
    let mut model = create_test_model();

    for i in 0..100 {
        model.add_tox_log(
            ToxLogLevel::TOX_LOG_LEVEL_DEBUG,
            "file.c".to_string(),
            i,
            "func".to_string(),
            format!("message {}", i),
        );
    }

    // Switch to logs window to test scrolling
    model.ui.window_ids.push(WindowId::Logs);
    model.set_active_window(1);

    let backend = TestBackend::new(80, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    model.scroll_up(1);
    assert_eq!(
        model
            .ui
            .window_state
            .get(&WindowId::Logs)
            .unwrap()
            .msg_list_state
            .scroll,
        1
    );

    model.scroll_down(1);
    assert_eq!(
        model
            .ui
            .window_state
            .get(&WindowId::Logs)
            .unwrap()
            .msg_list_state
            .scroll,
        0
    );

    model.scroll_down(1); // Should stay at 0
    assert_eq!(
        model
            .ui
            .window_state
            .get(&WindowId::Logs)
            .unwrap()
            .msg_list_state
            .scroll,
        0
    );
}

#[test]
fn test_save_load_state_with_logs() {
    let temp_dir =
        std::env::temp_dir().join(format!("toxxi_test_state_logs_{}", rand::random::<u32>()));
    fs::create_dir_all(&temp_dir).unwrap();

    let mut model = create_test_model();
    model.add_tox_log(
        ToxLogLevel::TOX_LOG_LEVEL_ERROR,
        "error.c".to_string(),
        404,
        "fail".to_string(),
        "Fatal error".to_string(),
    );

    toxxi::model::save_state(&temp_dir, &model).unwrap();
    let state = toxxi::model::load_state(&temp_dir)
        .expect("Failed to load state")
        .expect("State not found");

    assert_eq!(
        state
            .domain
            .tox_logs
            .get(&ToxLogLevel::TOX_LOG_LEVEL_ERROR)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        state
            .domain
            .tox_logs
            .get(&ToxLogLevel::TOX_LOG_LEVEL_ERROR)
            .unwrap()[0]
            .message,
        "Fatal error"
    );

    fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn test_save_load_state_with_filters() {
    let temp_dir = std::env::temp_dir().join(format!(
        "toxxi_test_state_filters_{}",
        rand::random::<u32>()
    ));
    fs::create_dir_all(&temp_dir).unwrap();

    let mut model = create_test_model();
    model.ui.log_filters.levels = vec![ToxLogLevel::TOX_LOG_LEVEL_ERROR];
    model.ui.log_filters.msg_pattern = Some("critical".to_string());

    toxxi::model::save_state(&temp_dir, &model).unwrap();
    let state = toxxi::model::load_state(&temp_dir)
        .expect("Failed to load state")
        .expect("State not found");

    assert_eq!(
        state.log_filters.levels,
        vec![ToxLogLevel::TOX_LOG_LEVEL_ERROR]
    );
    assert_eq!(state.log_filters.msg_pattern, Some("critical".to_string()));

    fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn test_logs_clear_and_all() {
    let mut model = create_test_model();

    // 1. Add some logs and set a filter
    model.add_tox_log(
        ToxLogLevel::TOX_LOG_LEVEL_INFO,
        "file.c".to_string(),
        1,
        "f".to_string(),
        "msg".to_string(),
    );
    toxxi::update::handle_command(&mut model, "/logs level=error");

    assert_eq!(model.all_tox_logs_unfiltered().len(), 1);
    assert_eq!(model.ui.log_filters.levels.len(), 1);

    // 2. Test /logs all (should clear filters but keep logs)
    toxxi::update::handle_command(&mut model, "/logs all");
    assert_eq!(model.ui.log_filters.levels.len(), 0);
    assert_eq!(model.all_tox_logs_unfiltered().len(), 1);

    // 3. Test /logs clear (should clear logs)
    toxxi::update::handle_command(&mut model, "/logs clear");
    assert_eq!(model.all_tox_logs_unfiltered().len(), 0);
}

#[test]
fn test_logs_pause_resume() {
    let mut model = create_test_model();

    // 1. Add a log
    model.add_tox_log(
        ToxLogLevel::TOX_LOG_LEVEL_INFO,
        "file.c".to_string(),
        1,
        "f".to_string(),
        "msg 1".to_string(),
    );
    assert_eq!(model.all_tox_logs().len(), 1);

    // 2. Pause
    toxxi::update::handle_command(&mut model, "/logs pause");
    assert!(model.ui.log_filters.paused);

    // 3. Add a log while paused
    model.add_tox_log(
        ToxLogLevel::TOX_LOG_LEVEL_INFO,
        "file.c".to_string(),
        2,
        "f".to_string(),
        "msg 2".to_string(),
    );
    // Should still have only 1 log
    assert_eq!(model.all_tox_logs().len(), 1);
    assert_eq!(model.all_tox_logs()[0].message, "msg 1");

    // 4. Resume
    toxxi::update::handle_command(&mut model, "/logs resume");
    assert!(!model.ui.log_filters.paused);

    // 5. Add a log after resuming
    model.add_tox_log(
        ToxLogLevel::TOX_LOG_LEVEL_INFO,
        "file.c".to_string(),
        3,
        "f".to_string(),
        "msg 3".to_string(),
    );
    // Should have 2 logs (msg 1 and msg 3)
    assert_eq!(model.all_tox_logs().len(), 2);
    assert_eq!(model.all_tox_logs()[0].message, "msg 1");
    assert_eq!(model.all_tox_logs()[1].message, "msg 3");
}

// end of tests
