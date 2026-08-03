const std = @import("std");

pub fn set_terminal(original_termios: std.posix.termios) !void {
    var raw = original_termios;
    raw.lflag.ICANON = false;
    raw.lflag.ECHO = false;
    try std.posix.tcsetattr(std.posix.STDOUT_FILENO, .NOW, raw);
}

pub fn set_terminal_password(original_termios: std.posix.termios) !void {
    var raw = original_termios;
    raw.lflag.ECHO = false;
    try std.posix.tcsetattr(std.posix.STDOUT_FILENO, .NOW, raw);
}

pub fn reset_terminal(original_termios: std.posix.termios) !void {
    try std.posix.tcsetattr(std.posix.STDOUT_FILENO, .NOW, original_termios);
}
