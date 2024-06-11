# libadb

This is an attempt to reimplement the host (and maybe client) side of the [Android Debug Bridge](https://en.wikipedia.org/wiki/Android_Debug_Bridge) such that it may embedded into other programs and be used independently of the official ADB binary. Please see [protocol.md](protocol.md) for more information about the protocol.

There is currently no actual library or header emitted while the implementation is confirmed to work on a wide range of devices, but it can be imported from other zig programs.

## Building

```sh
zig build --release=safe
```

## Importing from another zig project

Run this command from your project folder

```sh
zig fetch --save https://github.com/ssttevee/libadb/archive/refs/heads/trunk.tar.gz
```

Then add this snippet to your build.zig file

```zig
const adb = b.dependency("adb", .{
    .optimize = optimize,
    .target = target,
});

exe.root_module.addImport("adb", adb.module("adb"));
```

## Examples

There is currently only one example that simulates running `adb exec-out screencap -p`.

```sh
./zig-out/bin/example_screencap > screencap.png
```

## Additional notes

- Openssl is currently required. This dependency will likely be removed as soon as the necessary RSA and TLS operations are shipped in the zig std library.

- The TCP transport implementation is not currently working due to what seems to be an issue with the zig std library tls client.

- This library currently only supports single-threaded and single-socket operation. This will most likely only be addressed after ziglang/zig#6025 is fixed.
