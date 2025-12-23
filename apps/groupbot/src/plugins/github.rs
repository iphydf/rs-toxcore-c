use crate::plugin::{CommandContext, Plugin};
use serde::Deserialize;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use toxcore::tox::Tox;

#[derive(Deserialize, Debug, Clone)]
struct User {
    login: String,
}

#[derive(Deserialize, Debug, Clone)]
struct IssueData {
    number: u64,
    title: String,
    state: String,
    user: User,
}

pub struct GitHub {
    path: PathBuf,
}

type IssueResult = (String, Option<(IssueData, bool, String)>);

impl GitHub {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn find_issue(
        &self,
        repo_prefix: Option<&str>,
        issue_number: u64,
    ) -> Result<IssueResult, Box<dyn Error>> {
        let repo_dir = self.path.join("repositories");
        if !repo_dir.exists() {
            return Err("GitHub backup directory not found".into());
        }

        let mut candidates = Vec::new();
        let mut found_repo_name = "any repository".to_string();

        for entry in fs::read_dir(repo_dir)? {
            let entry = entry?;
            let name = entry.file_name().into_string().unwrap_or_default();

            if let Some(prefix) = repo_prefix
                && !name.to_lowercase().starts_with(&prefix.to_lowercase())
            {
                continue;
            }

            // Check issues
            let issues_path = entry
                .path()
                .join("issues")
                .join(format!("{}.json", issue_number));
            if issues_path.exists() {
                let data: IssueData = serde_json::from_reader(fs::File::open(issues_path)?)?;
                candidates.push((data, false, name.clone()));
            }

            // Check pulls
            let pulls_path = entry
                .path()
                .join("pulls")
                .join(format!("{}.json", issue_number));
            if pulls_path.exists() {
                let data: IssueData = serde_json::from_reader(fs::File::open(pulls_path)?)?;
                candidates.push((data, true, name.clone()));
            }

            if repo_prefix.is_some() {
                found_repo_name = name;
            }
        }

        let best = candidates
            .iter()
            .find(|(data, _, _)| data.state == "open")
            .cloned()
            .or_else(|| candidates.into_iter().next());

        Ok((found_repo_name, best))
    }
}

impl Plugin for GitHub {
    fn name(&self) -> &str {
        "gh"
    }

    fn on_command(
        &mut self,
        _bot: &Tox,
        _context: &CommandContext,
        args: &[String],
    ) -> Result<Option<String>, Box<dyn Error>> {
        if args.len() != 1 {
            return Ok(None);
        }

        let arg = &args[0];
        let (repo_prefix, issue_id_str) = if let Some(pos) = arg.find('#') {
            let (repo, rest) = arg.split_at(pos);
            let issue_id = &rest[1..];
            (if repo.is_empty() { None } else { Some(repo) }, issue_id)
        } else {
            (None, arg.as_str())
        };

        let issue_number: u64 = match issue_id_str.parse() {
            Ok(n) => n,
            Err(_) => return Ok(None),
        };

        let (_repo_name, issue) = self.find_issue(repo_prefix, issue_number)?;

        match issue {
            Some((data, is_pr, actual_repo)) => {
                let emoji = if is_pr { "🎁" } else { "🐛" };
                Ok(Some(format!(
                    "{} {} by {} ({}#{}, {})",
                    emoji, data.title, data.user.login, actual_repo, data.number, data.state
                )))
            }
            None => {
                if let Some(prefix) = repo_prefix {
                    Ok(Some(format!(
                        "Error: Issue {} not found in repository starting with {}",
                        issue_number, prefix
                    )))
                } else {
                    Ok(Some(format!("Error: Issue {} not found", issue_number)))
                }
            }
        }
    }
}
