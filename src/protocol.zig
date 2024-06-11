const std = @import("std");

/// ADB protocol version.
/// Version revision:
/// 0x01000000: original
/// 0x01000001: skip checksum (Dec 2017)
pub const Version = struct {
    pub const min = 0x01000000;
    const skip_checksum = 0x01000001;
    pub const current = 0x01000001;

    pub fn shouldSkipChecksum(version: u32) bool {
        return version >= skip_checksum;
    }
};

/// Stream-based TLS protocol version
const STLSVersion = struct {
    const min = 0x01000000;
    const current = 0x01000000;
};

const Command = enum(u32) {
    sync = 0x434e5953,
    cnxn = 0x4e584e43,
    open = 0x4e45504f,
    okay = 0x59414b4f,
    clse = 0x45534c43,
    wrte = 0x45545257,
    auth = 0x48545541,
    stls = 0x534C5453,

    fn magic(self: Command) u32 {
        return @as(u32, @intFromEnum(self)) ^ 0xFFFFFFFF;
    }
};

pub const Packet = struct {
    /// command identifier constant
    command: Command,

    /// arguments
    args: [2]u32,

    /// data payload
    data: []const u8 = &.{},

    pub const max_payload_size_v1 = 1 << 12;
    pub const max_payload_size = 1 << 20;
    pub const max_framework_payload = 1 << 16;

    pub const read_buf_size = max_payload_size + @sizeOf(Header);

    pub const Header = extern struct {
        command: Command,
        arg1: u32,
        arg2: u32,
        len: u32,
        check: u32,
        magic: u32,

        pub fn toPacket(self: Header, data: []const u8) Packet {
            std.debug.assert(@as(usize, @intCast(std.mem.littleToNative(u32, self.len))) == data.len);
            std.debug.assert(std.mem.littleToNative(u32, self.magic) == std.mem.littleToNative(Command, self.command).magic());

            // the version of adb we are implementing never checks the checksum
            // if (!skip_checksum) {
            //     std.debug.assert(std.mem.littleToNative(u32, self.check) == calculate_checksum(data));
            // }

            return .{
                .command = std.mem.littleToNative(Command, self.command),
                .args = .{
                    std.mem.littleToNative(u32, self.arg1),
                    std.mem.littleToNative(u32, self.arg2),
                },
                .data = data,
            };
        }
    };

    pub fn initConnect(max_data_len: u32, system_identity: []const u8) Packet {
        if (system_identity.len > max_payload_size_v1) {
            std.debug.panic("Connection banner is too long (length = {d})", .{system_identity.len});
        }

        return .{
            .command = .cnxn,
            .args = .{
                Version.current, // version
                max_data_len,
            },
            .data = system_identity,
        };
    }

    pub fn initAuthSignatureResponse(signature: []const u8) Packet {
        return .{
            .command = .auth,
            .args = .{ 2, 0 },
            .data = signature,
        };
    }

    /// The public key is expected to be encoded in the ["Android RSA
    /// public key binary format"](https://android.googlesource.com/platform/system/core/+/refs/tags/android-9.0.0_r45/libcrypto_utils/android_pubkey.c#122)
    pub fn initAuthPublicKeyResponse(public_key: []const u8) Packet {
        return .{
            .command = .auth,
            .args = .{ 3, 0 },
            .data = public_key,
        };
    }

    /// When delayed acks are supported, the initial number of unacknowledged bytes we're willing to
    /// receive on a socket before the other side should block.
    pub fn initOpen(socket_id: u32, delayed_ack_bytes: u32, destination: []const u8) Packet {
        std.debug.assert(socket_id != 0); // forbidden by the protocol

        return .{
            .command = .open,
            .args = .{ socket_id, delayed_ack_bytes },
            .data = destination,
        };
    }

    pub fn initOkay(local_socket_id: u32, remote_socket_id: u32) Packet {
        return .{
            .command = .okay,
            .args = .{ local_socket_id, remote_socket_id },
        };
    }

    pub fn initWrite(local_socket_id: u32, remote_socket_id: u32, data: []const u8) Packet {
        return .{
            .command = .okay,
            .args = .{ local_socket_id, remote_socket_id },
            .data = data,
        };
    }

    pub fn initClose(local_socket_id: u32, remote_socket_id: u32) Packet {
        return .{
            .command = .clse,
            .args = .{ local_socket_id, remote_socket_id },
        };
    }

    pub fn initTlsRequest() Packet {
        return .{
            .command = .stls,
            .args = .{ STLSVersion.current, 0 },
        };
    }

    fn calculate_checksum(data: []const u8) u32 {
        var sum: u32 = 0;
        for (data) |byte| {
            sum += @intCast(byte);
        }

        return sum;
    }

    pub fn seal(self: Packet, skip_checksum: bool) std.meta.Tuple(&.{ [24]u8, []const u8 }) {
        return .{
            @bitCast([_]u32{
                std.mem.nativeToLittle(u32, @intFromEnum(self.command)),
                std.mem.nativeToLittle(u32, self.args[0]),
                std.mem.nativeToLittle(u32, self.args[1]),
                std.mem.nativeToLittle(u32, @as(u32, @intCast(self.data.len))),
                if (skip_checksum) 0 else std.mem.nativeToLittle(u32, calculate_checksum(self.data)),
                std.mem.nativeToLittle(u32, self.command.magic()),
            }),
            self.data,
        };
    }

    pub fn format(self: Packet, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;

        var tag: [4]u8 = undefined;
        for (@tagName(self.command), 0..) |c, i| {
            tag[i] = std.ascii.toUpper(c);
        }

        const max_dump = 32;
        const body_len = @min(self.data.len, max_dump);
        var body: [max_dump]u8 = undefined;
        for (0..body_len) |i| {
            const x = self.data[i];

            // adb.cpp:230
            body[i] = if (x >= ' ' and x < 127) x else '.';
        }

        try std.fmt.format(writer, "{s} {x:0>8} {x:0>8} {x:0>4} \"{s}\"", .{ tag, self.args[0], self.args[1], self.data.len, body[0..body_len] });
    }
};
