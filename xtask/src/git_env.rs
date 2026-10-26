//! Keeps git's repository-local environment out of child processes.
//!
//! A git hook exports `GIT_DIR`, `GIT_INDEX_FILE` and their relatives to every
//! process it starts. A child that inherits them acts on the hook's repository,
//! whatever directory it runs in or names with `-C`, so a test fixture that
//! creates, commits to or tags a scratch repository would change the real one.
//! Every child that runs git, or runs something that does, is started without
//! them.

use std::process::Command;

/// The variables as git 2.x lists them, for when `git` cannot be asked.
const KNOWN: &[&str] = &[
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_OBJECT_DIRECTORY",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_GRAFT_FILE",
    "GIT_INDEX_FILE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_REPLACE_REF_BASE",
    "GIT_PREFIX",
    "GIT_SHALLOW_FILE",
    "GIT_COMMON_DIR",
];

/// git's repository-local environment variables, as
/// `git rev-parse --local-env-vars` lists them, together with the names git
/// 2.x lists. Needs no repository.
pub fn local_env_vars() -> Vec<String> {
    let mut vars: Vec<String> = KNOWN.iter().map(|v| (*v).to_owned()).collect();
    if let Ok(out) = Command::new("git")
        .args(["rev-parse", "--local-env-vars"])
        .output()
        && out.status.success()
    {
        for var in String::from_utf8_lossy(&out.stdout).lines() {
            if !vars.iter().any(|v| v == var) {
                vars.push(var.to_owned());
            }
        }
    }
    vars
}

/// `cmd`, set to start without git's repository-local environment.
pub fn without_repo_env(cmd: &mut Command) -> &mut Command {
    for var in local_env_vars() {
        cmd.env_remove(var);
    }
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_names_the_variables_a_hook_exports() {
        let vars = local_env_vars();
        for var in [
            "GIT_DIR",
            "GIT_INDEX_FILE",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
        ] {
            assert!(
                vars.iter().any(|v| v == var),
                "{var} is missing from {vars:?}"
            );
        }
    }

    #[test]
    fn a_cleared_command_removes_git_dir() {
        let mut cmd = Command::new("true");
        without_repo_env(&mut cmd);
        assert!(
            cmd.get_envs()
                .any(|(key, value)| key == "GIT_DIR" && value.is_none()),
            "GIT_DIR must be removed from the child's environment"
        );
    }
}
