//! Prints the messages in an account's event log, so a chat history can be
//! searched without the client. It only reads the log.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;

use chatlog::{Filter, lines, local, plain, read_events};
use chrono::{Local, NaiveDate, NaiveDateTime, TimeZone};
use clap::Parser;
use regex::RegexBuilder;

#[derive(Parser)]
#[command(about = "Prints the messages in an account's event log.")]
struct Args {
    /// Path to the event log (`events.log`).
    log: PathBuf,
    /// Only show chats whose name contains this text (ignoring case).
    #[arg(long)]
    chat: Option<String>,
    /// Only show senders whose name contains this text (ignoring case).
    #[arg(long)]
    from: Option<String>,
    /// Only show lines matching this regular expression (ignoring case).
    #[arg(long)]
    grep: Option<String>,
    /// Only show lines from this local time on: `2026-11-19` or `2026-11-19 13:00`.
    #[arg(long, value_parser = parse_time)]
    since: Option<i64>,
    /// Only show lines before this local time.
    #[arg(long, value_parser = parse_time)]
    until: Option<i64>,
    /// Only show the last N lines.
    #[arg(long)]
    last: Option<usize>,
    /// Also show joins, leaves, renames, topics, titles, files, calls and notices.
    #[arg(long)]
    events: bool,
    /// Print one JSON object per line.
    #[arg(long)]
    json: bool,
    /// List the chats with their line count and the time of their last line.
    #[arg(long)]
    chats: bool,
}

/// Parses a local date, or date and time, into milliseconds since the Unix epoch.
fn parse_time(text: &str) -> Result<i64, String> {
    let time = NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M")
        .or_else(|_| {
            NaiveDate::parse_from_str(text, "%Y-%m-%d").map(|d| d.and_time(Default::default()))
        })
        .map_err(|_| "expected YYYY-MM-DD or YYYY-MM-DD HH:MM".to_owned())?;
    Local
        .from_local_datetime(&time)
        .earliest()
        .map(|t| t.timestamp_millis())
        .ok_or_else(|| "no such local time".to_owned())
}

fn main() -> ExitCode {
    let args = Args::parse();
    let grep = match args
        .grep
        .as_deref()
        .map(|re| RegexBuilder::new(re).case_insensitive(true).build())
    {
        Some(Err(e)) => {
            eprintln!("--grep: {e}");
            return ExitCode::FAILURE;
        }
        Some(Ok(re)) => Some(re),
        None => None,
    };
    let (events, unread) = match read_events(&args.log) {
        Ok(read) => read,
        Err(e) => {
            eprintln!("{}: {e}", args.log.display());
            return ExitCode::FAILURE;
        }
    };
    if unread > 0 {
        eprintln!("{unread} records not understood, skipped");
    }
    let filter = Filter {
        chat: args.chat,
        from: args.from,
        grep,
        since: args.since,
        until: args.until,
        events: args.events,
        last: if args.chats { None } else { args.last },
    };
    let kept = filter.apply(lines(&events));
    if args.chats {
        let mut chats: HashMap<&str, (usize, i64)> = HashMap::new();
        for line in &kept {
            let chat = chats.entry(&line.chat).or_default();
            *chat = (chat.0 + 1, chat.1.max(line.time));
        }
        let mut chats: Vec<_> = chats.into_iter().collect();
        chats.sort_by_key(|&(_, (_, last))| last);
        for (name, (count, last)) in chats {
            println!("{}  {count:>6}  {name}", local(last));
        }
    } else {
        for line in &kept {
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string(line).expect("lines always encode")
                );
            } else {
                println!("{}", plain(line));
            }
        }
    }
    ExitCode::SUCCESS
}
