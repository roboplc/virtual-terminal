use std::time::Duration;

use tokio::{
    io::AsyncWriteExt,
    signal::unix::{signal, SignalKind},
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let (x, y) = terminal_size::terminal_size().unwrap();
    let cmd = virtual_terminal::Command::new("htop").terminal_size((x.0.into(), y.0.into()));
    let mut sigwinch = signal(SignalKind::window_change()).unwrap();
    let in_tx_winch = cmd.in_tx();
    tokio::spawn(async move {
        loop {
            sigwinch.recv().await.unwrap();
            let Some((x, y)) = terminal_size::terminal_size() else {
                continue;
            };
            in_tx_winch
                .send(virtual_terminal::Input::Resize((x.0.into(), y.0.into())))
                .await
                .ok();
        }
    });
    let out_rx = cmd.out_rx();
    let in_tx = cmd.in_tx();
    tokio::spawn(cmd.run());
    while let Ok(msg) = out_rx.recv().await {
        match msg {
            virtual_terminal::Output::Pid(_pid) => {
                let in_tx = in_tx.clone();
                tokio::spawn(async move {
                    for _ in 0..4 {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        in_tx
                            .send(virtual_terminal::Input::Data(b"#".to_vec()))
                            .await
                            .ok();
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    in_tx
                        .send(virtual_terminal::Input::Data(b"q".to_vec()))
                        .await
                        .ok();
                });
            }
            virtual_terminal::Output::Stdout(v) => {
                tokio::io::stdout().write_all(&v).await.unwrap();
                tokio::io::stdout().flush().await.unwrap();
            }
            virtual_terminal::Output::Terminated(exit_code) => {
                std::process::exit(exit_code.unwrap_or(-1));
            }
            virtual_terminal::Output::Error(e) => {
                eprintln!("{}", e);
                break;
            }
        }
    }
}
