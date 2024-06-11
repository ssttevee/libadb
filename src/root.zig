const std = @import("std");

pub const auth = @import("./auth.zig");
pub const host = @import("./host.zig");
pub const services = @import("./services.zig");
pub const Transport = @import("./transport.zig");

test {
    _ = auth;
    _ = host;
    _ = services;
}

pub const SystemBanner = struct {
    type: []const u8,
    product_name: []const u8,
    product_model: []const u8,
    product_device: []const u8,
    features: []const u8,

    pub fn parse(banner: []const u8) SystemBanner {
        var pieces = std.mem.splitScalar(u8, banner, ':');

        var self = SystemBanner{
            .type = pieces.next().?,
            .product_name = undefined,
            .product_model = undefined,
            .product_device = undefined,
            .features = undefined,
        };

        _ = pieces.next().?;
        var properties = std.mem.splitScalar(u8, pieces.next().?, ';');
        std.debug.assert(pieces.next() == null);

        while (properties.next()) |prop| {
            var pair = std.mem.split(u8, prop, "=");
            const key = if (pair.next()) |k| k else continue;
            const value = if (pair.next()) |v| v else continue;

            if (std.mem.eql(u8, key, "ro.product.name")) {
                self.product_name = value;
            } else if (std.mem.eql(u8, key, "ro.product.model")) {
                self.product_model = value;
            } else if (std.mem.eql(u8, key, "ro.product.device")) {
                self.product_device = value;
            } else if (std.mem.eql(u8, key, "features")) {
                self.features = value;
            }
        }

        return self;
    }

    pub fn deinit(self: SystemBanner) void {
        self.allocator.free(self.features);
    }

    pub fn iterateFeatures(self: SystemBanner) std.mem.SplitIterator(u8, .scalar) {
        return std.mem.splitScalar(u8, self.features, ',');
    }
};
