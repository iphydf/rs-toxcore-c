use toxxi::widgets::message_list::{WrappedLine, wrap_text};

#[test]
fn test_wrap_basic() {
    assert_eq!(
        wrap_text("hello world", 20),
        vec![WrappedLine {
            text: "hello world".to_string(),
            is_soft_wrap: false
        }]
    );
    assert_eq!(
        wrap_text("hello world", 5),
        vec![
            WrappedLine {
                text: "hello".to_string(),
                is_soft_wrap: true
            },
            WrappedLine {
                text: "world".to_string(),
                is_soft_wrap: false
            }
        ]
    );
}

#[test]
fn test_wrap_forced_break() {
    assert_eq!(
        wrap_text("abcdefghij", 5),
        vec![
            WrappedLine {
                text: "abcde".to_string(),
                is_soft_wrap: true
            },
            WrappedLine {
                text: "fghij".to_string(),
                is_soft_wrap: false
            }
        ]
    );
}

#[test]
fn test_wrap_unicode() {
    // 😊 is width 2
    assert_eq!(
        wrap_text("😊😊😊", 4),
        vec![
            WrappedLine {
                text: "😊😊".to_string(),
                is_soft_wrap: true
            },
            WrappedLine {
                text: "😊".to_string(),
                is_soft_wrap: false
            }
        ]
    );
}

#[test]
fn test_wrap_empty_and_whitespace() {
    assert_eq!(
        wrap_text("", 10),
        vec![WrappedLine {
            text: "".to_string(),
            is_soft_wrap: false
        }]
    );
    assert_eq!(
        wrap_text("\n", 10),
        vec![
            WrappedLine {
                text: "".to_string(),
                is_soft_wrap: false
            },
            WrappedLine {
                text: "".to_string(),
                is_soft_wrap: false
            }
        ]
    );
}

#[test]
fn test_wrap_multiple_spaces() {
    // When width is enough, spaces should be preserved
    assert_eq!(
        wrap_text("a  b", 10),
        vec![WrappedLine {
            text: "a  b".to_string(),
            is_soft_wrap: false
        }]
    );
}

#[test]
fn test_wrap_newlines() {
    assert_eq!(
        wrap_text("line1\nline2", 10),
        vec![
            WrappedLine {
                text: "line1".to_string(),
                is_soft_wrap: false
            },
            WrappedLine {
                text: "line2".to_string(),
                is_soft_wrap: false
            }
        ]
    );
}

#[test]
fn test_wrap_zero_width() {
    assert_eq!(
        wrap_text("hello", 0),
        vec![WrappedLine {
            text: "hello".to_string(),
            is_soft_wrap: false
        }]
    );
}

#[test]
fn test_wrap_very_narrow() {
    assert_eq!(
        wrap_text("abc", 1),
        vec![
            WrappedLine {
                text: "a".to_string(),
                is_soft_wrap: true
            },
            WrappedLine {
                text: "b".to_string(),
                is_soft_wrap: true
            },
            WrappedLine {
                text: "c".to_string(),
                is_soft_wrap: false
            }
        ]
    );
}

#[test]
fn test_wrap_cjk() {
    // "你好" is width 4 (2 each)
    assert_eq!(
        wrap_text("你好", 2),
        vec![
            WrappedLine {
                text: "你".to_string(),
                is_soft_wrap: true
            },
            WrappedLine {
                text: "好".to_string(),
                is_soft_wrap: false
            }
        ]
    );
}

#[test]
fn test_wrap_leading_trailing_spaces() {
    assert_eq!(
        wrap_text(" hello ", 10),
        vec![WrappedLine {
            text: " hello".to_string(),
            is_soft_wrap: false
        }]
    );
}
