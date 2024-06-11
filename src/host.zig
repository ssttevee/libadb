const std = @import("std");
const testing = std.testing;
const auth = @import("./auth.zig");

pub const Packet = @import("./protocol.zig").Packet;
pub const Transport = @import("./transport.zig");

test {
    _ = auth;
}

pub fn handshake(buf: []u8, transport: *Transport, keys: []const auth.Key, ca_bundle: ?std.crypto.Certificate.Bundle) !Packet {
    try transport.sendConnect(Packet.max_payload_size, "host::");

    var packet = try transport.readPacket(buf);
    if (packet.command == .stls) {
        try transport.sendTlsRequest();

        try transport.configureTLS(ca_bundle orelse .{}, &try auth.keyFingerprint(keys[0]));

        packet = try transport.readPacket(buf);
    }

    var i: usize = 0;
    while (packet.command == .auth and i < keys.len) : (i += 1) {
        std.debug.assert(packet.args[0] == 1); // this is always the case as the host, other values are never sent by the device

        // adb.cpp:437
        try transport.sendAuthSignatureResponse(&auth.sign(keys[i], packet.data));

        packet = try transport.readPacket(buf);
    }

    i = 0;
    while (packet.command == .auth and i < keys.len) : (i += 1) {
        std.debug.assert(packet.args[0] == 1); // this is always the case as the host, other values are never sent by the device

        try transport.sendAuthPublicKeyResponse(&try auth.encodePublicKey(keys[i]));

        packet = try transport.readPacket(buf);
    }

    std.debug.assert(packet.command == .cnxn);

    transport.remote_protocol_version = packet.args[0];
    transport.max_payload_size = packet.args[1];

    return packet;
}

pub fn openSocket(buf: []u8, transport: *Transport, service: []const u8, local_socket_id: u32) !Packet {
    try transport.sendOpen(local_socket_id, 0, service);

    const packet = try transport.readPacket(buf);

    std.debug.assert(packet.command == .okay);

    std.log.debug("remote socket is {d}", .{packet.args[0]});
    std.log.debug("local socket is {d}", .{packet.args[1]});

    std.debug.assert(local_socket_id == packet.args[1]);

    if (packet.data.len > 0) {
        std.debug.assert(packet.data.len == 4);
        std.log.debug("delayed ack bytes from server: {d}", .{std.mem.bytesToValue(u32, packet.data)});
    }

    return packet;
}
