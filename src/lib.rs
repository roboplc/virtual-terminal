#![deny(missing_docs)]
#![ doc = include_str!( concat!( env!( "CARGO_MANIFEST_DIR" ), "/", "README.md" ) ) ]
use libc::TIOCSCTTY;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
/// Output from the command
pub enum Output {
    /// The process id of the command, sent right after the command is started
    Pid(u32),
    /// Data from the command's stdout/stderr
    Stdout(Vec<u8>),
    /// Error messages
    Error(String),
    /// The command has terminated (with an optional exit code)
    Terminated(Option<i32>),
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
/// Input to the command
pub enum Input {
    /// Data to be sent to the command's stdin
    Data(Vec<u8>),
    /// Resize the virtual terminal
    Resize((usize, usize)),
    /// Terminate the command
    Terminate,
}

const BUF_SIZE: usize = 8192;

fn set_term_size(
    fd: i32,
    term_size: (usize, usize),
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let ws = libc::winsize {
        ws_row: u16::try_from(term_size.1)?,
        ws_col: u16::try_from(term_size.0)?,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) } != 0 {
        return Err("ioctl".into());
    }

    Ok(())
}

/// A command to be run in a virtual terminal
pub struct Command {
    pid: Option<u32>,
    program: OsString,
    args: Vec<OsString>,
    env: BTreeMap<OsString, OsString>,
    current_dir: Option<PathBuf>,
    in_tx: async_channel::Sender<Input>,
    in_rx: async_channel::Receiver<Input>,
    out_tx: async_channel::Sender<Output>,
    out_rx: async_channel::Receiver<Output>,
    terminal_id: String,
    terminal_size: (usize, usize),
    shutdown_timeout: Option<Duration>,
}

impl Command {
    /// Create a new command
    pub fn new<S: AsRef<OsStr>>(program: S) -> Self {
        let (in_tx, in_rx) = async_channel::bounded(BUF_SIZE);
        let (out_tx, out_rx) = async_channel::bounded(BUF_SIZE);
        Self {
            pid: None,
            program: program.as_ref().to_os_string(),
            args: <_>::default(),
            env: <_>::default(),
            current_dir: None,
            in_tx,
            in_rx,
            out_tx,
            out_rx,
            terminal_id: "screen-256color".to_string(),
            terminal_size: (80, 24),
            shutdown_timeout: None,
        }
    }
    /// Get the sender for sending input to the command
    pub fn in_tx(&self) -> async_channel::Sender<Input> {
        self.in_tx.clone()
    }
    /// Get the output sender, useful e.g. to manually send empty output frames to the terminal handler
    pub fn out_tx(&self) -> async_channel::Sender<Output> {
        self.out_tx.clone()
    }
    /// Get the receiver for receiving output from the command
    pub fn out_rx(&self) -> async_channel::Receiver<Output> {
        self.out_rx.clone()
    }
    /// Set the terminal id
    pub fn terminal_id<S: Into<String>>(mut self, terminal_id: S) -> Self {
        self.terminal_id = terminal_id.into();
        self
    }
    /// Set the terminal size
    pub fn terminal_size(mut self, terminal_size: (usize, usize)) -> Self {
        self.terminal_size = terminal_size;
        self
    }
    /// Set the shutdown timeout to collect the command output
    pub fn shutdown_timeout(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout = Some(timeout);
        self
    }
    /// Set the program arguments
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args = args
            .into_iter()
            .map(|s| s.as_ref().to_os_string())
            .collect();
        self
    }
    /// Add a program argument
    pub fn arg<S: AsRef<OsStr>>(mut self, arg: S) -> Self {
        self.args.push(arg.as_ref().to_os_string());
        self
    }
    /// Set the environment variables
    pub fn envs<I, K, V>(mut self, env: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.env = env
            .into_iter()
            .map(|(k, v)| (k.as_ref().to_os_string(), v.as_ref().to_os_string()))
            .collect();
        self
    }
    /// Add an environment variable
    pub fn env<K: AsRef<OsStr>, V: AsRef<OsStr>>(mut self, key: K, value: V) -> Self {
        self.env
            .insert(key.as_ref().to_os_string(), value.as_ref().to_os_string());
        self
    }
    /// Set the working directory
    pub fn current_dir<P: AsRef<Path>>(mut self, current_dir: P) -> Self {
        self.current_dir = Some(current_dir.as_ref().to_path_buf());
        self
    }
    /// Run the command
    pub async fn run(self) {
        let out_tx = self.out_tx.clone();
        match self.run_subprocess().await {
            Ok(v) => {
                out_tx.send(Output::Terminated(v)).await.ok();
            }
            Err(e) => {
                out_tx.send(Output::Error(e.to_string())).await.ok();
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn run_subprocess(
        mut self,
    ) -> Result<Option<i32>, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let win_size = rustix::termios::Winsize {
            ws_col: self.terminal_size.0.try_into()?,
            ws_row: self.terminal_size.1.try_into()?,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let pty = rustix_openpty::openpty(None, Some(&win_size))?;
        let (master, slave) = (pty.controller, pty.user);

        let master_fd = master.as_raw_fd();
        let slave_fd = slave.as_raw_fd();

        if let Ok(mut termios) = rustix::termios::tcgetattr(&master) {
            // Set character encoding to UTF-8.
            termios
                .input_modes
                .set(rustix::termios::InputModes::IUTF8, true);
            let _ = rustix::termios::tcsetattr(
                &master,
                rustix::termios::OptionalActions::Now,
                &termios,
            );
        }

        let mut builder = tokio::process::Command::new(&self.program);

        if let Some(ref current_dir) = self.current_dir {
            builder.current_dir(current_dir);
        }

        builder
            .args(&self.args)
            .envs(&self.env)
            .env("COLUMNS", self.terminal_size.0.to_string())
            .env("LINES", self.terminal_size.1.to_string())
            .env("TERM", &self.terminal_id);

        builder.stdin(slave.try_clone()?);
        builder.stderr(slave.try_clone()?);
        builder.stdout(slave);

        unsafe {
            builder.pre_exec(move || {
                let err = libc::setsid();
                if err == -1 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Failed to set session id",
                    ));
                }

                let res = libc::ioctl(slave_fd, TIOCSCTTY as _, 0);
                if res == -1 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to set controlling terminal: {}", res),
                    ));
                }

                libc::close(slave_fd);
                libc::close(master_fd);

                libc::signal(libc::SIGCHLD, libc::SIG_DFL);
                libc::signal(libc::SIGHUP, libc::SIG_DFL);
                libc::signal(libc::SIGINT, libc::SIG_DFL);
                libc::signal(libc::SIGQUIT, libc::SIG_DFL);
                libc::signal(libc::SIGTERM, libc::SIG_DFL);
                libc::signal(libc::SIGALRM, libc::SIG_DFL);

                Ok(())
            });
        }

        let mut child = builder.spawn()?;

        let pid = child.id().ok_or("unable to get child pid")?;

        self.out_tx.send(Output::Pid(pid)).await?;
        self.pid = Some(pid);

        let mut stdout = File::from_std(std::fs::File::from(master));

        let mut stdin = stdout.try_clone().await?;

        let tx_stdout = self.out_tx.clone();

        let fut_out = tokio::spawn(async move {
            let mut buf = [0u8; BUF_SIZE];
            while let Ok(b) = stdout.read(&mut buf).await {
                if b == 0 {
                    break;
                }
                if tx_stdout
                    .send(Output::Stdout(buf[..b].to_vec()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        let shutdown_timeout = self.shutdown_timeout;

        let fut_in = tokio::spawn(async move {
            while let Ok(input) = self.in_rx.recv().await {
                let mut data = match input {
                    Input::Data(d) => d,
                    Input::Resize(size) => {
                        set_term_size(stdin.as_raw_fd(), size).ok();
                        bmart::process::kill_pstree_with_signal(
                            pid,
                            bmart::process::Signal::SIGWINCH,
                            true,
                        );
                        continue;
                    }
                    Input::Terminate => {
                        break;
                    }
                };
                // TODO: remove this input hack
                if data == [0x0a] {
                    data[0] = 0x0d;
                }
                if stdin.write_all(&data).await.is_err() {
                    break;
                }
            }
        });

        let result = child.wait().await?;

        // TODO: fix this
        if let Some(t) = shutdown_timeout {
            for _ in 0..10 {
                if fut_out.is_finished() {
                    break;
                }
                tokio::time::sleep(t / 10).await;
            }
        }

        fut_out.abort();
        fut_in.abort();

        let exit_code = result.code();

        Ok(exit_code)
    }
}

impl Drop for Command {
    fn drop(&mut self) {
        if let Some(pid) = self.pid {
            tokio::spawn(bmart::process::kill_pstree(
                pid,
                Some(Duration::from_secs(1)),
                true,
            ));
        }
    }
}
