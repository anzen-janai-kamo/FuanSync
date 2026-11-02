use fuansync::{
    Result, auth, binary,
    cli::{self, Action, Operation},
    install, protocol,
    record::{self, Credentials, MAX_PEM},
};
use std::{
    env,
    fs::File,
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

fn read_pem(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    let file = File::open(path).map_err(|_| "cannot open PEM file")?;
    if !file
        .metadata()
        .map_err(|_| "cannot inspect PEM file")?
        .is_file()
    {
        return Err("PEM path must refer to a regular file");
    }
    file.take((MAX_PEM + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read PEM file")?;
    if bytes.is_empty() || bytes.len() > MAX_PEM {
        return Err("PEM must contain between 1 byte and 64 KiB");
    }
    Ok(bytes)
}

fn run() -> Result<()> {
    let source = env::current_exe().map_err(|_| "cannot locate current executable")?;
    let executable =
        Zeroizing::new(std::fs::read(&source).map_err(|_| "cannot read current executable")?);
    let embedded = binary::embedded_record(&executable)?.and_then(record::decode);
    let has_credentials = embedded.is_some();
    let action = cli::parse(env::args_os().skip(1), has_credentials)?;
    let options = match action {
        Action::Help => {
            print!("{}", cli::help(has_credentials));
            return Ok(());
        }
        Action::Version => {
            println!("fuansync {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Action::Run(options) => options,
    };
    if !options.embed {
        protocol::validate_input(std::io::stdin().lock())?;
        if options.operation != Operation::Get {
            return Ok(());
        }
    }
    let credentials = match embedded {
        Some(credentials) => credentials,
        None => Credentials {
            app: options.app.ok_or("--app is required")?,
            installation: options.installation.ok_or("--installation is required")?,
            pem: read_pem(options.pem.as_deref().ok_or("--pem is required")?)?,
        },
    };
    record::validate(&credentials)?;
    if options.embed {
        auth::validate_pem(&credentials.pem)?;
        let record = record::encode(&credentials)?;
        let output = binary::embed(&executable, &record)?;
        let path = if let Some(path) = options.output {
            install::write_output(&path, &source, &output, options.force)?
        } else {
            install::install(
                &env::current_dir().map_err(|_| "cannot locate current directory")?,
                &source,
                &output,
                options.force,
            )?
        };
        eprintln!("FuanSync helper written to {}", path.display());
    } else {
        let token = auth::installation_token(&credentials)?;
        let response = Zeroizing::new(format!("username=x-access-token\npassword={}\n\n", *token));
        std::io::stdout()
            .lock()
            .write_all(response.as_bytes())
            .map_err(|_| "cannot write Git credential output")?;
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("fuansync: {error}");
        std::process::exit(1);
    }
}
