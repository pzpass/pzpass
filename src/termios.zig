const std = @import("std");

pub fn set_terminal(original_termios: std.posix.termios) !void {
    var raw = original_termios;
    raw.lflag.ICANON = false;
    raw.lflag.ECHO = false;
    try std.posix.tcsetattr(std.Io.File.stdout().handle, .NOW, raw);
}

pub fn set_terminal_pasword(original_termios: std.posix.termios) !void {
    var raw = original_termios;
    raw.lflag.ECHO = false;
    try std.posix.tcsetattr(std.Io.File.stdout().handle, .NOW, raw);
}

pub fn set_terminal_confirm(original_termios: std.posix.termios) !void {
    var raw = original_termios;
    raw.lflag.ICANON = false;
    try std.posix.tcsetattr(std.Io.File.stdout().handle, .NOW, raw);
}

pub fn reset_terminal(original_termios: std.posix.termios) void {
    std.posix.tcsetattr(std.Io.File.stdout().handle, .NOW, original_termios) catch unreachable;
}
