# iOS interface

This library exposes two methods that allow our iOS Swift example app to use the prove / verify mechanics from the core code base.

## Compilation instructions

 - Add the target architectures to `rustup` to enable cross compilation.

```
rustup target add aarch64-apple-ios x86_64-apple-ios
```

 - Install `cargo-lipo`.

```
cargo install cargo-lipo
```

 - Compile the library

```
cargo lipo --release
```

 - And done! Take note of the location of the compiled universal library `.a` file, you'll need it on the xcode side.
