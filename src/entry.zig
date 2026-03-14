const std = @import("std");

pub const Entry = struct {
    name: []u8,
    username: []u8,
    password: []u8,
    url: []u8,
    notes: []u8,
};
