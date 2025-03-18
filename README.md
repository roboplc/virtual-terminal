<h2>
  Virtual Terminal for Rust
  <a href="https://crates.io/crates/virtual-terminal"><img alt="crates.io page" src="https://img.shields.io/crates/v/virtual-terminal.svg"></img></a>
  <a href="https://docs.rs/virtual-terminal"><img alt="docs.rs page" src="https://docs.rs/virtual-terminal/badge.svg"></img></a>
</h2>

Async virtual terminal for Rust. Allows to spawn/communicate with a process in
a virtual terminal (Linux only).

The communication is performed through async channels, so it is possible to
communicate with a program e.g. on a remote machine via custom API/transport.

## Issues

While the terminal side is pretty simple to implement, major issues may arise
from the client side as the spawned process may require special input/output
handling.

The terminal itself has been tested with the majority of traditional
complicated programs, such as `vim`, `screen`, `tmux`, `mc` etc. and works
pretty well.
