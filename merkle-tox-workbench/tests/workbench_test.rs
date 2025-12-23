use merkle_tox_workbench::model::{Model, Topology};
use merkle_tox_workbench::msg::Msg;
use merkle_tox_workbench::update::update;
use std::time::Duration;

#[test]
fn test_initial_state() {
    let model = Model::new(2, 0, 1.0, true, 4, Topology::Mesh);
    assert_eq!(model.nodes.len(), 2);
    assert!(model.is_paused);
}

#[test]
fn test_tick_advances_time() {
    let mut model = Model::new(2, 0, 1.0, false, 4, Topology::Mesh);
    let initial_steps = model.steps;
    let dt = Duration::from_millis(50);

    update(&mut model, Msg::Tick(dt));

    assert_eq!(model.steps, initial_steps + 1);
    assert_eq!(model.virtual_elapsed, dt);
}

#[test]
fn test_pause_toggle() {
    let mut model = Model::new(2, 0, 1.0, true, 4, Topology::Mesh);
    assert!(model.is_paused);

    // Simulate space key
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
    let event = crossterm::event::Event::Key(KeyEvent {
        code: KeyCode::Char(' '),
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    });

    update(&mut model, Msg::Input(event));
    assert!(!model.is_paused);
}
