To build binary on OSX for deployment

Add this to ~/.cargo/config.toml

``` toml
[target.x86_64-unknown-linux-musl]
linker = "x86_64-linux-musl-gcc"
```

Install Dependencies
``` sh
rustup target add x86_64-unknown-linux-musl
brew install FiloSottile/musl-cross/musl-cross
```

Build
``` sh
cargo build --release --target x86_64-unknown-linux-musl
```


