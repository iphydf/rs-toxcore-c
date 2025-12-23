use ratatui::{Terminal, backend::TestBackend, layout::Rect};
use toxxi::testing::{buffer_to_string, configure_insta};
use toxxi::widgets::Oscilloscope;

#[test]
fn test_render_oscilloscope() {
    let backend = TestBackend::new(20, 5);
    let mut terminal = Terminal::new(backend).unwrap();
    let data: Vec<f32> = (0..50)
        .map(|i| (i as f32 * std::f32::consts::PI * 2.0 / 50.0).sin())
        .collect();
    let widget = Oscilloscope {
        data,
        ..Default::default()
    };

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 20, 5);
            f.render_widget(widget, area);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("oscilloscope", rendered);
    });
}

#[test]
fn test_render_oscilloscope_unfilled() {
    let backend = TestBackend::new(20, 5);
    let mut terminal = Terminal::new(backend).unwrap();
    let data: Vec<f32> = (0..50)
        .map(|i| (i as f32 * std::f32::consts::PI * 2.0 / 50.0).sin())
        .collect();
    let widget = Oscilloscope {
        data,
        fill: false,
        ..Default::default()
    };

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 20, 5);
            f.render_widget(widget, area);
        })
        .unwrap();

    let rendered = buffer_to_string(terminal.backend().buffer());
    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("oscilloscope_unfilled", rendered);
    });
}

#[test]
fn test_render_oscilloscope_filled() {
    let backend = TestBackend::new(10, 5);
    let mut terminal = Terminal::new(backend).unwrap();
    // A single high peak
    let widget = Oscilloscope {
        data: vec![1.0],
        ..Default::default()
    };

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 10, 5);
            f.render_widget(widget, area);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();

    // In a "filled" oscilloscope, a peak of 1.0 at height 5 should have dots
    // from the middle (y=2.5) up to the top (y=0).
    // Let's check if there are multiple braille dots in the first column.
    let char = buffer[(0, 0)].symbol().chars().next().unwrap();
    let code = char as u32 - 0x2800;
    assert!(code > 0, "Top cell should have dots set for filled peak");

    let char_mid = buffer[(0, 2)].symbol().chars().next().unwrap_or(' ');
    let code_mid = if ('\u{2800}'..='\u{28FF}').contains(&char_mid) {
        char_mid as u32 - 0x2800
    } else {
        0
    };
    assert!(
        code_mid > 0,
        "Middle cell should have dots set for filled peak"
    );
}

#[test]
fn test_render_oscilloscope_no_zero_line() {
    let backend = TestBackend::new(10, 5);
    let mut terminal = Terminal::new(backend).unwrap();
    // Empty data but show_zero_line is true by default
    let widget = Oscilloscope {
        data: vec![],
        show_zero_line: true,
        ..Default::default()
    };

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 10, 5);
            f.render_widget(widget, area);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();
    let char_mid = buffer[(0, 2)].symbol().chars().next().unwrap_or(' ');
    assert_ne!(char_mid, ' ', "Zero line should be visible");

    // Now disable zero line
    let widget = Oscilloscope {
        data: vec![],
        show_zero_line: false,
        ..Default::default()
    };

    terminal
        .draw(|f| {
            let area = Rect::new(0, 0, 10, 5);
            f.render_widget(widget, area);
        })
        .unwrap();

    let buffer = terminal.backend().buffer();
    let char_mid = buffer[(0, 2)].symbol().chars().next().unwrap_or(' ');
    assert_eq!(char_mid, ' ', "Zero line should NOT be visible");
}

// end of file
