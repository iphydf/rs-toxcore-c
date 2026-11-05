use toxxi::widgets::message_list::{WrappedLine, wrap_text};

#[test]
fn test_wrap_text() {
    let cases = [
        ("hello world", 20, vec![("hello world", false)]),
        ("hello world", 5, vec![("hello", true), ("world", false)]),
        ("abcdefghij", 5, vec![("abcde", true), ("fghij", false)]),
        (
            "ExtremelyLongWord",
            5,
            vec![
                ("Extre", true),
                ("melyL", true),
                ("ongWo", true),
                ("rd", false),
            ],
        ),
        ("abc", 1, vec![("a", true), ("b", true), ("c", false)]),
        ("hello", 0, vec![("hello", false)]),
        ("😊😊😊", 4, vec![("😊😊", true), ("😊", false)]),
        ("你好", 2, vec![("你", true), ("好", false)]),
        ("你好世界", 4, vec![("你好", true), ("世界", false)]),
        ("Hello 你好", 6, vec![("Hello", true), ("你好", false)]),
        ("", 10, vec![("", false)]),
        ("\n", 10, vec![("", false), ("", false)]),
        ("line1\nline2", 10, vec![("line1", false), ("line2", false)]),
        (
            "Line 1\n\nLine 3",
            10,
            vec![("Line 1", false), ("", false), ("Line 3", false)],
        ),
        ("a  b", 10, vec![("a  b", false)]),
        (" hello ", 10, vec![(" hello", false)]),
    ];
    for (input, width, expected) in cases {
        let expected: Vec<WrappedLine> = expected
            .into_iter()
            .map(|(text, is_soft_wrap)| WrappedLine {
                text: text.to_string(),
                is_soft_wrap,
            })
            .collect();
        assert_eq!(
            wrap_text(input, width),
            expected,
            "{input:?} at width {width}"
        );
    }
}
