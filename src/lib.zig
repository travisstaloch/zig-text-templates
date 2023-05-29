const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;

const Token = enum(u8) {
    literal,
    directive_start,
    directive_end,
    eof,
};

const Range = struct { usize, ?usize };

/// represents a for loop
const For = struct {
    /// expressions between parens ie 'for (e1, e2)'
    exprs: []const Expression,
    /// capture group names
    names: []const []const u8,
    /// the validated length of each expression
    range_len: usize,
    /// current loop index
    loop_index: usize,

    fn get(for_: For, n: []const u8) ?Expression {
        for (for_.exprs, 0..) |e, i| if (mem.eql(u8, for_.names[i], n)) return e;
        return null;
    }

    pub fn format(for_: For, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt;
        _ = try writer.write("for (");
        for (for_.exprs, 0..) |e, i| {
            if (i != 0) _ = try writer.write(", ");
            try writer.print("{}", .{e});
        }
        _ = try writer.write(") |");
        for (for_.names, 0..) |n, i| {
            if (i != 0) _ = try writer.write(", ");
            _ = try writer.write(n);
        }
        _ = try writer.write("|");
    }
};

pub const Expression = union(enum) {
    literal: []const u8,
    ws_literal: []const u8,
    name: []const u8,
    for_: For,
    if_: []const Expression,
    range: Range,
    end,
    op: Op,
    number: usize,

    const Tag = std.meta.Tag(Expression);

    pub fn format(expr: Expression, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        _ = try writer.write(@tagName(expr));
        switch (expr) {
            .range => |r| try writer.print("={}..{?}", .{ r[0], r[1] }),
            .op => |op| try writer.print("={s}", .{@tagName(op)}),
            .number => |number| try writer.print("={d}", .{number}),
            .end => {},
            inline else => |s| try writer.print("={s}", .{s}),
        }
    }
};

fn compileError(comptime fmt: []const u8, args: anytype) void {
    @compileError(std.fmt.comptimePrint(fmt, args));
}

fn escape(comptime input: []const u8, comptime m_end: ?[]const u8) ![]u8 {
    var ifbs = std.io.fixedBufferStream(input);
    var output: [input.len]u8 = undefined;
    var ofbs = std.io.fixedBufferStream(&output);
    const reader = ifbs.reader();
    const writer = ofbs.writer();
    while (true) {
        if (m_end) |end|
            if (mem.startsWith(u8, ifbs.buffer, end)) break;
        const byte = reader.readByte() catch break;
        if (byte != '\\') try writer.writeByte(byte);
    }
    return ofbs.getWritten();
}

const Lexer = struct {
    buf: []const u8,

    pub fn init(buf: []const u8) Lexer {
        return .{ .buf = buf };
    }

    pub fn nextToken(l: *Lexer) Token {
        if (l.buf.len < 2) return .literal;
        switch (std.mem.readIntBig(u16, l.buf[0..2])) {
            std.mem.readIntBig(u16, "{{") => {
                l.buf = l.buf[2..];
                return .directive_start;
            },
            std.mem.readIntBig(u16, "}}") => {
                l.buf = l.buf[2..];
                return .directive_end;
            },
            else => return if (l.buf.len > 0) .literal else .eof,
        }
        unreachable;
    }

    pub fn skip(l: *Lexer, count: usize) void {
        l.buf = l.buf[count..];
    }

    pub fn readUntil(l: *Lexer, s: []const u8) ?[]const u8 {
        if (mem.indexOf(u8, l.buf, s)) |i| {
            defer l.buf = l.buf[i..];
            return l.buf[0..i];
        }
        return null;
    }

    pub fn consume(l: *Lexer, s: []const u8) bool {
        if (mem.startsWith(u8, l.buf, s)) {
            l.buf = l.buf[s.len..];
            return true;
        }
        return false;
    }

    pub fn readUntilOrErr(
        l: *Lexer,
        s: []const u8,
        comptime fmt: []const u8,
        args: anytype,
        err: Error,
    ) Error![]const u8 {
        const result = l.readUntil(s) orelse {
            compileError(fmt ++ ". found '{s}'", args ++ .{l.buf});
            return err;
        };
        return result;
    }

    pub fn consumeOrErr(
        l: *Lexer,
        s: []const u8,
        comptime fmt: []const u8,
        args: anytype,
        err: Error,
    ) Error!void {
        if (!l.consume(s)) {
            compileError(fmt ++ ". found '{s}'", args ++ .{l.buf});
            return err;
        }
    }

    pub fn skipWhitespace(l: *Lexer) void {
        while (l.buf.len > 0 and
            std.ascii.isWhitespace(l.buf[0])) : (l.buf = l.buf[1..])
        {}
    }

    pub fn next(comptime l: *Lexer) !?Expression {
        l.skipWhitespace();
        return switch (l.nextToken()) {
            .eof => null,
            .directive_start => if (l.readUntil("}}")) |content| blk: {
                if (content.len > 0 and content[0] == '%')
                    break :blk .{ .ws_literal = content[1..] };
                const trimmed = trimSpaces(content);
                break :blk if (mem.startsWith(u8, trimmed, "for"))
                    .{ .for_ = comptime try parseFor(trimmed) }
                else if (mem.startsWith(u8, trimmed, "if"))
                    .{ .if_ = comptime try parseIf(trimmed) }
                else if (mem.eql(u8, trimmed, "end"))
                    .end
                else
                    .{ .name = trimmed };
            } else error.UnmatchedDirectiveStart,
            .directive_end => if (l.readUntil("{{")) |content|
                .{ .literal = content }
            else
                null,
            .literal => if (l.readUntil("{{")) |s|
                .{ .literal = try escape(s, null) }
            else if (l.buf.len > 0) blk: {
                defer l.buf = l.buf[l.buf.len..];
                break :blk .{
                    .literal = try escape(l.buf, null),
                };
            } else null,
        };
    }
};

fn trimSpaces(s: []const u8) []const u8 {
    return mem.trim(u8, s, &std.ascii.whitespace);
}

fn maybeName(s: []const u8) ?[]const u8 {
    if (s.len > 0 and std.ascii.isAlphabetic(s[0])) {
        return for (s[1..]) |c| {
            if (!(std.ascii.isAlphanumeric(c) or c == '_')) break null;
        } else s;
    }
    return null;
}

test maybeName {
    try std.testing.expect(maybeName("") == null);
}

fn maybeNumber(s: []const u8) ?[]const u8 {
    return for (s) |c| {
        if (!std.ascii.isDigit(c)) break null;
    } else if (s.len == 0)
        null
    else
        s;
}

test maybeNumber {
    try std.testing.expect(maybeNumber("") == null);
}

const Error = error{ MissingField, InvalidFor, UnmatchedDirectiveStart } ||
    std.io.FixedBufferStream([]u8).WriteError ||
    std.fmt.ParseIntError;

const Scope = struct {
    parent: ?*Scope,
    depth: u16,
    data: union(enum) {
        for_: For,
        if_: []const Expression,
    },

    pub fn format(s: Scope, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.print(
            "Scope range_len={} depth={} loop_index={} exprs.len={} parent={*}",
            .{ s.data.for_.range_len, s.depth, s.data.for_.loop_index, s.exprs.keys().len, s.parent },
        );
    }
};

pub fn parseFor(comptime s: []const u8) Error!For {
    comptime {
        assert(mem.startsWith(u8, s, "for"));
        var l = Lexer.init(trimSpaces(s[3..]));
        const paren_contents = blk: {
            try l.consumeOrErr("(", "error: expecting '('", .{}, error.InvalidFor);
            const paren_contents = trimSpaces(try l.readUntilOrErr(
                ")",
                "expecting ')'",
                .{},
                error.InvalidFor,
            ));
            l.skip(1);
            l.skipWhitespace();
            break :blk paren_contents;
        };

        var paren_iter = mem.split(u8, paren_contents, ",");
        var exprs: []const Expression = &.{};
        while (paren_iter.next()) |expr| {
            const m_range: ?Range = rg: {
                var rgiter = mem.split(u8, expr, "..");
                const low = trimSpaces(rgiter.next() orelse break :rg null);
                const hi = trimSpaces(rgiter.next() orelse
                    break :rg if (std.fmt.parseInt(usize, low, 10)) |v|
                    .{ v, null }
                else |_|
                    null);
                if (hi.len == 0)
                    break :rg .{ try std.fmt.parseInt(usize, low, 10), null };
                if (rgiter.rest().len != 0) {
                    compileError("for: invalid range '{s}'", .{rgiter.rest()});
                    return error.InvalidFor;
                }
                break :rg Range{
                    try std.fmt.parseInt(usize, low, 10),
                    try std.fmt.parseInt(usize, hi, 10),
                };
            };

            if (m_range) |range| {
                exprs = exprs ++ .{.{ .range = range }};
            } else if (maybeName(trimSpaces(expr))) |name| {
                exprs = exprs ++ .{.{ .name = name }};
            } else {
                compileError("for: expecting range or name. found '{s}'", .{expr});
                return error.InvalidFor;
            }
        }

        if (exprs.len == 0) {
            compileError("empty for loop parens.", .{});
            return error.InvalidFor;
        }
        try l.consumeOrErr("|", "expecting capture start '|'", .{}, error.InvalidFor);
        const capture_contents = trimSpaces(try l.readUntilOrErr(
            "|",
            "expecting capture end '|'",
            .{},
            error.InvalidFor,
        ));
        var capture_iter = mem.split(u8, capture_contents, ",");
        const capture_names = blk: {
            var capture_names: [exprs.len][]const u8 = undefined;
            var cap_i: usize = 0;
            while (capture_iter.next()) |raw_name| : (cap_i += 1) {
                if (maybeName(trimSpaces(raw_name))) |name| {
                    if (cap_i >= capture_names.len) {
                        compileError("extra for loop capture", .{});
                        return error.InvalidFor;
                    }
                    capture_names[cap_i] = name;
                } else {
                    compileError("invalid name in for loop capture '{s}'.", .{raw_name});
                    return error.InvalidFor;
                }
            }
            break :blk capture_names[0..cap_i];
        };
        if (capture_names.len < exprs.len) {
            compileError("missing for loop capture", .{});
            return error.InvalidFor;
        }
        return .{
            .exprs = exprs,
            .names = capture_names,
            .range_len = undefined,
            .loop_index = 0,
        };
    }
}

/// verify loop ranges
///   - for full ranges and lists: all lengths must be equal
///   - for unbounded ranges: do nothing
///   - must have atleast one upper bound
fn validateFor(for_: For, args: anytype) !usize {
    const first_full_range: [2]usize = for (for_.exprs) |pe| {
        switch (pe) {
            .range => |r| if (r[1]) |r1| break .{ r[0], r1 },
            .name => |n| if (fieldLen(args, n)) |len| break .{ 0, len } else {
                std.log.err("error: for loop item '{s}' with no len field", .{n});
                return error.InvalidFor;
            },
            else => unreachable,
        }
    } else {
        std.log.err("error: for loop with no upper bound", .{});
        return error.InvalidFor;
    };
    const range_len = first_full_range[1] - first_full_range[0];

    for (for_.exprs) |pe| {
        const r: [2]usize = switch (pe) {
            .range => |r| if (r[1]) |r1| .{ r[0], r1 } else continue,
            .name => |n| if (fieldLen(args, n)) |len| .{ @as(usize, 0), len } else {
                std.log.err("error: for loop item with no len field", .{});
                return error.InvalidFor;
            },
            else => unreachable,
        };

        const this_rg_len = r[1] - r[0];
        if (range_len != this_rg_len) {
            std.log.err(
                "error: for loop length mismatch. range {}..{}:{} != {}..{}:{}",
                .{ first_full_range[0], first_full_range[1], range_len, r[0], r[1], this_rg_len },
            );
            return error.InvalidFor;
        }
    }

    return range_len;
}

fn fieldLen(args: anytype, field_name: []const u8) ?usize {
    const Args = @TypeOf(args);
    const args_info = @typeInfo(Args);
    std.log.debug("fieldLen() field_name={s} args_info=.{s}", .{ field_name, @tagName(args_info) });
    switch (args_info) {
        .Struct => |info| if (info.fields.len == 0)
            return null
        else if (field_name.len == 0) {
            if (info.is_tuple) return info.fields.len;
        },
        .Array, .Vector => return args.len,
        else => {},
    }
    const FE = std.meta.FieldEnum(Args);
    if (std.meta.stringToEnum(FE, field_name)) |fe| {
        switch (fe) {
            inline else => |tag| {
                const T = std.meta.FieldType(Args, tag);
                std.log.debug("fieldLen T={}", .{T});
                switch (@typeInfo(T)) {
                    .Array, .Vector => return @field(args, @tagName(tag)).len,
                    .Pointer => |info| switch (info.size) {
                        .Slice => return @field(args, @tagName(tag)).len,
                        .One => return fieldLen(@field(args, @tagName(tag)).*, ""),
                        else => todo(".Pointer .{s}", .{@tagName(info)}),
                    },
                    .Struct => |info| if (info.is_tuple) return info.fields.len,
                    else => {},
                }
            },
        }
    }
    return null;
}

const Op = enum {
    @"!=",
    @"==",
    @"<",
    @">",
    @"<=",
    @">=",
};

pub fn parseIf(comptime s: []const u8) Error![]const Expression {
    comptime {
        assert(mem.startsWith(u8, s, "if"));
        var l = Lexer.init(trimSpaces(s[2..]));
        const paren_contents = blk: {
            try l.consumeOrErr("(", "error: expecting '('", .{}, error.InvalidFor);
            const paren_contents = trimSpaces(try l.readUntilOrErr(")", "expecting ')'", .{}, error.InvalidFor));
            l.skip(1);
            l.skipWhitespace();
            break :blk paren_contents;
        };
        var result: []const Expression = &.{};
        var iter = std.mem.tokenize(u8, paren_contents, &std.ascii.whitespace);
        inline while (iter.next()) |part| {
            if (maybeName(part)) |n|
                result = result ++ .{.{ .name = n }}
            else if (std.meta.stringToEnum(Op, part)) |op|
                result = result ++ .{.{ .op = op }}
            else if (maybeNumber(part)) |n|
                result = result ++ .{.{ .number = try std.fmt.parseInt(usize, n, 10) }}
            else
                todo("'{s}'", .{part});
        }
        return result;
    }
}

pub fn Template(
    comptime fmt: []const u8,
    comptime options: struct { eval_branch_quota: usize = 1000 },
) type {
    @setEvalBranchQuota(options.eval_branch_quota);
    const build_exprs = comptime blk: {
        var build_exprs: []const Expression = &.{};
        var lexer = Lexer.init(fmt);

        while (lexer.next() catch |e|
            std.debug.panic("error: {s}", .{@errorName(e)})) |expr|
        {
            if (expr != .literal or expr.literal.len != 0) {
                build_exprs = build_exprs ++ .{expr};
            }
        }
        if (build_exprs.len > 1) {
            // remove whitespace only literals which are between 2 non literals
            var new_build_exprs = build_exprs[0..build_exprs.len].*;
            var len: usize = 1; // always include the first one
            var iter = mem.window(Expression, build_exprs, 3, 1);
            inline while (iter.next()) |window| {
                if (window[1] == .literal and window[0] != .literal and window[2] != .literal) {
                    if (trimSpaces(window[1].literal).len == 0) {
                        continue;
                    }
                }
                new_build_exprs[len] = window[1];
                len += 1;
            }
            // always include the last one
            new_build_exprs[len] = build_exprs[build_exprs.len - 1];
            break :blk new_build_exprs[0 .. len + 1];
        } else break :blk build_exprs;
    };

    return struct {
        pub const exprs: []const Expression = build_exprs;

        pub fn format(writer: anytype, args: anytype) !void {
            var frags: []const Expression = exprs;
            try formatImpl(writer, args, &frags);
            if (frags.len != 0) {
                std.debug.panic(
                    "internal error: didn't render all exprs. {} weren't rendered. remaining: {any}",
                    .{ frags.len, frags },
                );
            }
        }

        pub fn bufPrint(buf: []u8, args: anytype) Error![]u8 {
            if (exprs.len == 0) return buf[0..0];
            var fbs = std.io.fixedBufferStream(buf);
            try format(fbs.writer(), args);
            return fbs.getWritten();
        }

        pub fn allocPrint(allocator: mem.Allocator, args: anytype) ![]u8 {
            var cwriter = std.io.countingWriter(std.io.null_writer);
            try format(cwriter.writer(), args);
            var buf = try allocator.alloc(u8, cwriter.bytes_written);
            return bufPrint(buf, args);
        }

        fn formatImpl(
            writer: anytype,
            args: anytype,
            frags: *[]const Expression,
        ) Error!void {
            while (frags.len > 0) {
                _ = try formatFrag(writer, args, frags, null);
            }
        }

        fn formatFrag(
            writer: anytype,
            args: anytype,
            frags: *[]const Expression,
            scope: ?*Scope,
        ) Error!void {
            const frag = frags.*[0];
            std.log.info("formatFrag() frags.len={} frag=.{s}", .{ frags.len, @tagName(frag) });
            switch (frag) {
                .end => {},
                .range, .op, .number => unreachable,
                .literal, .ws_literal => |s| _ = try writer.write(s),
                .name => |name| try formatFieldScoped(name, scope, writer, args),
                .for_ => |for_| {
                    var child_scope = Scope{
                        .parent = scope,
                        .depth = if (scope) |p| p.depth + 1 else 0,
                        .data = .{ .for_ = for_ },
                    };
                    child_scope.data.for_.range_len = try validateFor(for_, args);
                    return try formatForLoop(writer, args, &child_scope, frags);
                },
                .if_ => |if_exprs| {
                    var child_scope = Scope{
                        .parent = scope,
                        .depth = if (scope) |s| s.depth + 1 else 0,
                        .data = .{ .if_ = if_exprs },
                    };
                    return try formatIf(writer, args, &child_scope, frags);
                },
            }
            frags.* = frags.*[1..];
        }

        fn formatFieldScoped(field_name: []const u8, scope: ?*Scope, writer: anytype, args: anytype) !void {
            const Args = @TypeOf(args);
            const args_info = @typeInfo(Args);
            std.log.info(
                "formatFieldScoped() field_name={s} args_info=.{s} args={any}",
                .{ field_name, @tagName(args_info), args },
            );
            switch (args_info) {
                .Struct => |sinfo| {
                    if (sinfo.fields.len == 0) {
                        // if empty struct, check scopes for field. error if not found
                        var cur = scope;
                        while (cur) |sc| : (cur = sc.parent) {
                            const e = sc.data.for_.get(field_name) orelse continue;
                            switch (e) {
                                .range => |r| return try writer.print("{}", .{sc.data.for_.loop_index + r[0]}),
                                else => todo("{}", .{e}),
                            }
                        } else return error.MissingField;
                    } else if (sinfo.is_tuple) {
                        if (scope) |sc| {
                            inline for (0..sinfo.fields.len) |fieldi| {
                                std.log.info(
                                    "tuple loop_index={} fieldi={}",
                                    .{ sc.data.for_.loop_index, fieldi },
                                );
                                if (sc.data.for_.loop_index == fieldi)
                                    return formatFieldScoped(field_name, scope, writer, args[fieldi]);
                            }
                        }
                    }
                    // check args fields for field_name
                    const FE = std.meta.FieldEnum(Args);
                    if (std.meta.stringToEnum(FE, field_name)) |fe| {
                        switch (fe) {
                            inline else => |tag| {
                                const T = std.meta.FieldType(Args, tag);
                                std.log.debug("field={s}", .{field_name});
                                switch (@typeInfo(T)) {
                                    .Pointer => |info| if (comptime std.meta.trait.isZigString(T)) {
                                        _ = try writer.write(@field(args, @tagName(tag)));
                                        return;
                                    } else switch (info.size) {
                                        .One => return formatFieldScoped("", scope, writer, @field(args, @tagName(tag)).*),
                                        .Slice => return formatFieldScoped("", scope, writer, @field(args, @tagName(tag))),
                                        else => todo(".Pointer .{s}", .{@tagName(info.size)}),
                                    },
                                    .Struct,
                                    .Array,
                                    => return formatFieldScoped(field_name, scope, writer, @field(args, @tagName(tag))),
                                    else => |info| todo(".{s}", .{@tagName(info)}),
                                }
                            },
                        }
                    }
                    // didn't find field_name in args. check scopes
                    var cur = scope;
                    while (cur) |sc| : (cur = sc.parent) {
                        if (sc.data.for_.get(field_name)) |expr| {
                            std.log.debug("scope field={s} expr={}", .{ field_name, expr });
                            switch (expr) {
                                .range => |r| return writer.print("{}", .{r[0] + sc.data.for_.loop_index}),
                                .name => |n| return formatFieldScoped(n, sc, writer, args),
                                else => todo("{}", .{expr}),
                            }
                        }
                    }
                },
                .Array => if (scope) |sc| {
                    std.log.info(".Array sc.data.for_.loop_index={}", .{sc.data.for_.loop_index});
                    return formatFieldScoped(field_name, scope, writer, args[sc.data.for_.loop_index]);
                },
                .Pointer => |info| if (comptime std.meta.trait.isZigString(Args)) {
                    _ = try writer.write(args);
                    return;
                } else switch (info.size) {
                    .One => return formatFieldScoped(field_name, scope, writer, args.*),
                    .Slice => if (scope) |sc|
                        return formatFieldScoped(field_name, scope, writer, args[sc.data.for_.loop_index]),
                    else => todo(".Pointer .{s} {}", .{ @tagName(info.size), args }),
                },
                else => |info| todo(".{s}", .{@tagName(info)}),
            }
            return error.MissingField;
        }

        fn formatForLoop(
            writer: anytype,
            args: anytype,
            scope: *Scope,
            frags: *[]const Expression,
        ) Error!void {
            assert(frags.len > 0 and frags.*[0] == .for_);
            assert(scope.data == .for_);
            frags.* = frags.*[1..];

            std.log.info("renderForLoop() frags.len={} range_len={} depth={}", .{ frags.len, scope.data.for_.range_len, scope.depth });

            for (0..scope.data.for_.range_len) |i| {
                scope.data.for_.loop_index = i;
                var frags_copy = frags.*;

                while (frags_copy.len != 0 and frags_copy[0] != .end) {
                    std.log.debug("i={} frags_copy.len={}", .{ i, frags_copy.len });
                    try formatFrag(writer, args, &frags_copy, scope);
                }
                if (i == scope.data.for_.range_len - 1) frags.* = frags.*[frags.len - frags_copy.len ..];
            }
        }

        fn evalInt(expr: Expression, args: anytype, scope: ?*Scope) !usize {
            const Args = @TypeOf(args);
            return switch (expr) {
                .name => |n| blk: {
                    var cur = scope;
                    while (cur) |sc| : (cur = sc.parent) {
                        switch (sc.data) {
                            .for_ => |for_| {
                                if (for_.get(n)) |e| {
                                    break :blk for_.loop_index + e.range[0];
                                }
                            },
                            .if_ => {},
                        }
                    }
                    const args_info = @typeInfo(Args);
                    if (args_info == .Struct and args_info.Struct.fields.len == 0)
                        return error.MissingField;
                    const FE = std.meta.FieldEnum(Args);
                    if (std.meta.stringToEnum(FE, n)) |fe| {
                        switch (fe) {
                            inline else => |tag| {
                                const T = std.meta.FieldType(Args, tag);
                                const tinfo = @typeInfo(T);
                                switch (tinfo) {
                                    .Int, .ComptimeInt => return @field(args, @tagName(tag)),
                                    .Bool => return @boolToInt(@field(args, @tagName(tag))),
                                    else => {},
                                }
                            },
                        }
                    }
                    std.log.err("missing field '{s}'", .{n});
                    return error.MissingField;
                },
                .number => |n| n,
                else => |e| todo("{}", .{e}),
            };
        }

        fn eval(if_exprs: []const Expression, args: anytype, scope: ?*Scope) !bool {
            switch (if_exprs.len) {
                1 => return try evalInt(if_exprs[0], args, scope) != 0,
                3 => {
                    const x = try evalInt(if_exprs[0], args, scope);
                    const op = if_exprs[1].op;
                    const y = try evalInt(if_exprs[2], args, scope);
                    return switch (op) {
                        .@"!=" => x != y,
                        .@"==" => x == y,
                        .@"<" => x < y,
                        .@">" => x > y,
                        .@"<=" => x <= y,
                        .@">=" => x >= y,
                    };
                },
                else => |n| todo("eval {}", .{n}),
            }
        }

        fn skip(frags: *[]const Expression) !void {
            while (frags.len != 0) : (frags.* = frags.*[1..]) {
                switch (frags.*[0]) {
                    .for_, .if_ => {
                        frags.* = frags.*[1..];
                        return skip(frags);
                    },
                    .end => break,
                    else => {},
                }
            }
        }

        fn formatIf(
            writer: anytype,
            args: anytype,
            scope: *Scope,
            frags: *[]const Expression,
        ) Error!void {
            assert(frags.len > 0 and frags.*[0] == .if_);
            assert(scope.data == .if_);
            const if_frag = frags.*[0];
            frags.* = frags.*[1..];

            std.log.info("renderIf() frags.len={} depth={} if_frag={}", .{ frags.len, scope.depth, if_frag });

            if (try eval(scope.data.if_, args, scope)) {
                while (frags.len != 0 and frags.*[0] != .end) {
                    try formatFrag(writer, args, frags, scope);
                }
            } else try skip(frags);
        }
    };
}

fn todo(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.panic("TODO " ++ fmt, args);
}
