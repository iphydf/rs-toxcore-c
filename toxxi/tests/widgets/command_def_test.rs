use toxxi::commands::CommandDef;

#[test]
fn test_to_widget_command_mapping() {
    let def = CommandDef {
        name: "test",
        args: (None, "<arg1> [arg2]"),
        desc: (None, "Does something useful"),
        exec: |_, _| vec![],
        complete: None,
    };

    let widget_cmd = def.to_widget_command();
    assert_eq!(widget_cmd.name, "test");
    assert_eq!(widget_cmd.args, "<arg1> [arg2]");
    assert_eq!(widget_cmd.description, "Does something useful");

    let def_no_args = CommandDef {
        name: "test2",
        args: (None, ""),
        desc: (None, "Just a description"),
        exec: |_, _| vec![],
        complete: None,
    };

    let widget_cmd2 = def_no_args.to_widget_command();
    assert_eq!(widget_cmd2.name, "test2");
    assert_eq!(widget_cmd2.args, "");
    assert_eq!(widget_cmd2.description, "Just a description");
}
