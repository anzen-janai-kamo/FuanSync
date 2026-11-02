use crate::Result;
use std::{ffi::OsString, path::PathBuf};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Get,
    Store,
    Erase,
}

pub struct Options {
    pub operation: Operation,
    pub app: Option<u64>,
    pub installation: Option<u64>,
    pub pem: Option<PathBuf>,
    pub embed: bool,
    pub output: Option<PathBuf>,
    pub force: bool,
}

pub enum Action {
    Help,
    Version,
    Run(Options),
}

fn id(value: Option<OsString>) -> Result<u64> {
    let value = value.ok_or("missing numeric argument")?;
    let value = value.to_str().ok_or("invalid numeric argument")?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("IDs must be positive unsigned 64-bit integers");
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|id| *id > 0)
        .ok_or("IDs must be positive unsigned 64-bit integers")
}

pub fn parse(arguments: impl IntoIterator<Item = OsString>, embedded: bool) -> Result<Action> {
    let mut arguments = arguments.into_iter();
    let mut options = Options {
        operation: Operation::Get,
        app: None,
        installation: None,
        pem: None,
        embed: false,
        output: None,
        force: false,
    };
    let mut operation = false;
    let mut help = false;
    let mut version = false;
    for_arg_loop(
        &mut arguments,
        embedded,
        &mut options,
        &mut operation,
        &mut help,
        &mut version,
    )?;
    if help && version {
        return Err("choose either --help or --version");
    }
    if help {
        return Ok(Action::Help);
    }
    if version {
        return Ok(Action::Version);
    }
    if embedded {
        if !operation {
            return Err("embedded helper requires get, store or erase");
        }
    } else if options.app.is_none() || options.installation.is_none() || options.pem.is_none() {
        return Err("--app, --installation and --pem are required");
    }
    if !options.embed && (options.output.is_some() || options.force) {
        return Err("-o and -f require --embed");
    }
    if options.embed && operation {
        return Err("--embed cannot be combined with a helper operation");
    }
    Ok(Action::Run(options))
}

fn for_arg_loop(
    arguments: &mut impl Iterator<Item = OsString>,
    embedded: bool,
    options: &mut Options,
    operation: &mut bool,
    help: &mut bool,
    version: &mut bool,
) -> Result<()> {
    while let Some(argument) = arguments.next() {
        let argument = argument.to_str().ok_or("invalid command line argument")?;
        if embedded && !matches!(argument, "get" | "store" | "erase" | "--help" | "--version") {
            return Err("embedded helper rejects credential and embedding arguments");
        }
        match argument {
            "--help" => {
                if *help {
                    return Err("duplicate --help");
                }
                *help = true;
            }
            "--version" => {
                if *version {
                    return Err("duplicate --version");
                }
                *version = true;
            }
            "get" | "store" | "erase" => {
                if *operation {
                    return Err("duplicate helper operation");
                }
                *operation = true;
                options.operation = match argument {
                    "get" => Operation::Get,
                    "store" => Operation::Store,
                    _ => Operation::Erase,
                };
            }
            "--app" => {
                if options.app.is_some() {
                    return Err("duplicate --app");
                }
                options.app = Some(id(arguments.next())?);
            }
            "--installation" => {
                if options.installation.is_some() {
                    return Err("duplicate --installation");
                }
                options.installation = Some(id(arguments.next())?);
            }
            "--pem" => {
                if options.pem.is_some() {
                    return Err("duplicate --pem");
                }
                options.pem = Some(PathBuf::from(
                    arguments.next().ok_or("--pem requires a file path")?,
                ));
            }
            "--embed" => {
                if options.embed {
                    return Err("duplicate --embed");
                }
                options.embed = true;
            }
            "-o" => {
                if options.output.is_some() {
                    return Err("duplicate -o");
                }
                options.output = Some(PathBuf::from(
                    arguments.next().ok_or("-o requires an output path")?,
                ));
            }
            "-f" => {
                if options.force {
                    return Err("duplicate -f");
                }
                options.force = true;
            }
            _ => return Err("unknown command line argument"),
        }
    }
    Ok(())
}

pub fn help(embedded: bool) -> &'static str {
    if embedded {
        "FuanSync embedded credential helper\nUsage: fuansync <get|store|erase|--help|--version>\n"
    } else {
        "FuanSync GitHub App credential helper\nUsage: fuansync --app <id> --installation <id> --pem <file> [get|store|erase]\n       fuansync --embed --app <id> --installation <id> --pem <file> [-o <output>] [-f]\nDefault operation: get. Without -o, --embed installs in the current Git repository.\n"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(arguments: &[&str]) -> Vec<OsString> {
        arguments.iter().map(OsString::from).collect()
    }
    #[test]
    fn modes_and_duplicate_arguments() {
        for forbidden in [
            "--app",
            "--installation",
            "--pem",
            "--embed",
            "-f",
            "-o",
            "secret",
        ] {
            assert!(parse(args(&["--help", forbidden]), true).is_err());
        }
        for allowed in ["get", "store", "erase", "--help", "--version"] {
            assert!(parse(args(&[allowed]), true).is_ok());
        }
        assert!(parse(args(&[]), true).is_err());
        assert!(
            parse(
                args(&["--app", "1", "--installation", "2", "--pem", "key"]),
                false
            )
            .is_ok()
        );
        for bad in [
            vec!["--app", "0"],
            vec!["--app", "-1"],
            vec!["--app", "18446744073709551616"],
            vec!["get", "get"],
            vec!["--help", "--app", "1", "--app", "2"],
        ] {
            assert!(parse(args(&bad), false).is_err());
        }
    }
}
