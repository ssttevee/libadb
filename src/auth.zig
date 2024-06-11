const std = @import("std");
const c = @cImport({
    @cInclude("openssl/rsa.h");
    @cInclude("openssl/pem.h");
});

test {
    _ = c;
}

pub const Key = *opaque {
    pub fn deinit(self: Key) void {
        c.RSA_free(@ptrCast(self));
    }
};

pub fn readKeyFile(allocator: std.mem.Allocator, file: []const u8) !Key {
    const f = try std.fs.openFileAbsolute(file, .{});
    defer f.close();

    const buf = try f.readToEndAlloc(allocator, std.math.maxInt(usize));

    const bio = c.BIO_new(c.BIO_s_mem());
    defer c.BIO_free_all(bio);

    _ = c.BIO_write(bio, buf.ptr, @intCast(buf.len));

    var key: ?*c.RSA = c.RSA_new();
    const retkey = c.PEM_read_bio_RSAPrivateKey(bio, &key, null, null);
    std.debug.assert(retkey == key);
    std.debug.assert(key != null);

    return @ptrCast(key.?);
}

fn generateKey(allocator: std.mem.Allocator, file: []const u8) !Key {
    const key = c.RSA_generate_key(2048, c.RSA_F4, null, null);
    errdefer c.RSA_free(key);

    const bio = c.BIO_new(c.BIO_s_mem());
    defer c.BIO_free_all(bio);

    _ = c.PEM_write_bio_RSAPrivateKey(bio, key, null, null, 0, null, null);

    const keylen = c.BIO_pending(bio);
    const pem_key = try allocator.allocSentinel(u8, keylen, 0);
    defer allocator.free(pem_key);

    _ = c.BIO_read(bio, pem_key.ptr, @intCast(pem_key.len));

    const f = try std.fs.openFileAbsolute(file, .{ .mode = .write_only });
    defer f.close();

    try f.writeAll(pem_key);

    return @ptrCast(key.?);
}

/// returns a pkcs1 encoded sha1 signature of the token
pub fn sign(key: Key, token: []const u8) [256]u8 {
    std.debug.assert(token.len == 20); // client/auth.cpp:261

    var result: [256]u8 = undefined;
    var len: c_uint = @intCast(result.len);
    if (c.RSA_sign(c.NID_sha1, token.ptr, @intCast(token.len), &result, &len, @ptrCast(key)) != 1) {
        @panic("rsa sign failed");
    }

    return result;
}

/// ported from https://android.googlesource.com/platform/system/core/+/refs/heads/android14-release/libcrypto_utils/android_pubkey.cpp
const RSA2048PublicKey = extern struct {
    const modulus_size = 2048 / 8;

    /// Modulus length. This must be modulus_size / 4
    modulus_size_words: u32 = modulus_size / 4,

    /// Precomputed montgomery parameter: -1 / n[0] mod 2^32
    n0inv: u32,

    /// RSA modulus as a little-endian array.
    modulus: [modulus_size]u8,

    // Montgomery parameter R^2 as a little-endian array.
    rr: [modulus_size]u8,

    // RSA modulus: 3 or 65537
    exponent: u32,

    test {
        try std.testing.expectEqual((3 * @sizeOf(u32) + 2 * modulus_size), @sizeOf(RSA2048PublicKey));
    }

    fn encode(key: Key) !RSA2048PublicKey {
        if (c.RSA_size(@ptrCast(key)) != modulus_size) {
            return error.UnsupportedKeySize;
        }

        const ctx = c.BN_CTX_new();
        defer c.BN_CTX_free(ctx);

        const r32 = c.BN_new();
        defer c.BN_free(r32);

        const n0inv = c.BN_new();
        defer c.BN_free(n0inv);

        if (ctx == null or r32 == null or n0inv == null) {
            return error.OutOfMemory;
        }

        // Compute and store n0inv = -1 / N[0] mod 2^32.
        if (c.BN_set_bit(r32, 32) == 0 or
            c.BN_div(null, n0inv, c.RSA_get0_n(@ptrCast(key)), r32, ctx) == 0 or
            c.BN_mod_inverse(n0inv, n0inv, r32, ctx) == null or
            c.BN_sub(n0inv, r32, n0inv) == 0)
        {
            return error.OperationFailed;
        }

        const rr = c.BN_new();
        defer c.BN_free(rr);

        if (rr == null) {
            return error.OutOfMemory;
        }

        // Compute and store rr = (2^(rsa_size)) ^ 2 mod N.
        var rr_bytes: [modulus_size]u8 = undefined;
        if (c.BN_set_bit(rr, modulus_size * 8) == 0 or
            c.BN_mod_sqr(rr, rr, c.RSA_get0_n(@ptrCast(key)), ctx) == 0 or
            c.BN_bn2lebinpad(rr, &rr_bytes, modulus_size) < 0)
        {
            return error.OperationFailed;
        }

        // Store the modulus.
        var modulus_bytes: [modulus_size]u8 = undefined;
        if (c.BN_bn2lebinpad(c.RSA_get0_n(@ptrCast(key)), &modulus_bytes, modulus_size) < 0) {
            return error.OperationFailed;
        }

        return .{
            .n0inv = @intCast(c.BN_get_word(n0inv)),
            .modulus = modulus_bytes,
            .rr = rr_bytes,
            .exponent = @intCast(c.BN_get_word(c.RSA_get0_e(@ptrCast(key)))),
        };
    }
};

test {
    _ = RSA2048PublicKey;
}

pub fn encodePublicKey(key: Key) ![std.base64.standard.Encoder.calcSize(@sizeOf(RSA2048PublicKey))]u8 {
    var buf: [std.base64.standard.Encoder.calcSize(@sizeOf(RSA2048PublicKey))]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&buf, &std.mem.toBytes(try RSA2048PublicKey.encode(key)));
    return buf;
}

pub fn keyFingerprint(key: Key) ![c.SHA256_DIGEST_LENGTH * 2]u8 {
    var dkey: [*c]u8 = null;
    defer c.CRYPTO_free(dkey, "", 0);

    const len: usize = @intCast(c.i2d_RSA_PUBKEY(@ptrCast(key), &dkey));

    var digest: [c.SHA256_DIGEST_LENGTH]u8 = undefined;
    _ = c.SHA256(dkey, len, &digest);

    var hex: [c.SHA256_DIGEST_LENGTH * 2]u8 = undefined;
    for (digest, 0..) |b, i| {
        _ = try std.fmt.bufPrint(hex[i * 2 ..], "{X:0>2}", .{b});
    }

    std.debug.print("fingerprint: {s}\n", .{hex});

    return hex;
}

// test "issuer" {
//     const key = try readKeyFile(std.testing.allocator, "/Users/steve/.android/adbkey");
//     defer key.deinit();

//     const name = c.X509_NAME_new();
//     defer c.X509_NAME_free(name);

//     var dkey: [*c]u8 = null;
//     defer c.OPENSSL_free(dkey);

//     const len = c.i2d_RSA_PUBKEY(@ptrCast(key), &dkey);

//     var digest: [c.SHA256_DIGEST_LENGTH]u8 = undefined;
//     _ = c.SHA256(dkey, len, digest);

//     const keyversion = "AdbKey-0";
//     c.X509_NAME_add_entry_by_NID(name, c.NID_organizationName, c.MBSTRING_ASC, keyversion, keyversion.len, -1, 0);
//     c.X509_NAME_add_entry_by_NID(name, c.NID_commonName, c.MBSTRING_ASC, keyversion, keyversion.len, -1, 0);
// }
