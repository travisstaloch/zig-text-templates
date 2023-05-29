const std = @import("std");
const lib = @import("lib.zig");
const Template = lib.Template;
const Expression = lib.Expression;
const parseFor = lib.parseFor;
const parseIf = lib.parseIf;

const t = std.testing;
const expectEqualDeep = @import("testing.zig").expectEqualDeep;

var test_buf: [1000]u8 = undefined;

test lib {
    _ = lib;
}

test "literal" {
    {
        const text = "";
        const tmpl = Template(text, .{});
        try t.expectEqual(tmpl.exprs.len, 0);
        try t.expectEqualStrings(text, try tmpl.bufPrint(&test_buf, .{}));
    }
    {
        const text: []const u8 = "hello";
        const tmpl = Template(text, .{});
        try expectEqualDeep(@as([]const Expression, &.{
            .{ .literal = text },
        }), tmpl.exprs);
        try t.expectEqualStrings(text, try tmpl.bufPrint(&test_buf, .{}));
    }
    {
        const text = "}{hello{}";
        const tmpl = Template(text, .{});
        try expectEqualDeep(@as([]const Expression, &.{
            .{ .literal = text },
        }), tmpl.exprs);
    }
}

test "escapes" {
    const tmpl = Template("\\{\\{0\\}\\}", .{});
    try expectEqualDeep(@as([]const Expression, &.{
        .{ .literal = "{{0}}" },
    }), tmpl.exprs);
}

test "named" {
    const text = "Hi {{name}} at index #{{index}}";
    const tmpl = Template(text, .{});
    try expectEqualDeep(@as([]const Expression, &.{
        .{ .literal = "Hi " },
        .{ .name = "name" },
        .{ .literal = " at index #" },
        .{ .name = "index" },
    }), tmpl.exprs);
    try t.expectEqualStrings("Hi zero at index #000", try tmpl.bufPrint(&test_buf, .{ .name = "zero", .index = "000" }));
}

test "for range" {
    const text =
        \\{{ for(0..2) |index| }}{{index}}{{ end }}
    ;
    const tmpl = Template(text, .{});
    try expectEqualDeep(@as([]const Expression, &.{
        .{ .for_ = comptime try parseFor("for(0..2) |index|") },
        .{ .name = "index" },
        .end,
    }), tmpl.exprs);
    try t.expectEqualStrings("01", try tmpl.bufPrint(&test_buf, .{}));
}

test "for range list" {
    const text =
        \\{{ for(list, 0..) |item, index| }}
        \\  {{% }}{{index}}={{item}}
        \\{{ end }}
    ;
    const tmpl = Template(text, .{});
    try expectEqualDeep(@as([]const Expression, &.{
        .{ .for_ = comptime try parseFor("for(list, 0..) |item, index|") },
        .{ .ws_literal = " " },
        .{ .name = "index" },
        .{ .literal = "=" },
        .{ .name = "item" },
        .end,
    }), tmpl.exprs);
    try t.expectEqualStrings(" 0=a 1=b", try tmpl.bufPrint(&test_buf, .{ .list = &.{ "a", "b" } }));
}

test "for range multiple" {
    const text =
        \\{{ for(list, 0..) |item, index| }}
        \\  {{ for(0..2) |index2| }}
        \\    {{index}},{{item}},{{index2}}{{%
        \\}}{{ end }}
        \\{{ end }}
    ;
    const tmpl = Template(text, .{ .eval_branch_quota = 2000 });
    try expectEqualDeep(@as([]const Expression, &.{
        .{ .for_ = comptime try parseFor("for(list, 0..) |item, index|") },
        .{ .for_ = comptime try parseFor("for(0..2) |index2|") },
        .{ .name = "index" },
        .{ .literal = "," },
        .{ .name = "item" },
        .{ .literal = "," },
        .{ .name = "index2" },
        .{ .ws_literal = "\n" },
        .end,
        .end,
    }), tmpl.exprs);
    try t.expectEqualStrings(
        \\0,a,0
        \\0,a,1
        \\1,b,0
        \\1,b,1
        \\
    , try tmpl.bufPrint(&test_buf, .{ .list = &.{ "a", "b" } }));
}

test "if" {
    const text =
        \\{{ for(list, 0..) |item, index| }}
        \\  {{index}}={{item}}
        \\  {{ if (index == 0) }}{{% }}{{end}}
        \\{{ end }}
    ;
    const tmpl = Template(text, .{});
    try expectEqualDeep(@as([]const Expression, &.{
        .{ .for_ = comptime try parseFor("for(list, 0..) |item, index|") },
        .{ .name = "index" },
        .{ .literal = "=" },
        .{ .name = "item" },
        .{ .if_ = comptime try parseIf("if (index == 0)") },
        .{ .ws_literal = " " },
        .end,
        .end,
    }), tmpl.exprs);

    try t.expectEqualStrings("0=a 1=b", try tmpl.bufPrint(&test_buf, .{ .list = &.{ "a", "b" } }));
}

test "if fields" {
    const text =
        \\{{ if (x) }}foo{{ end }}
    ;
    const tmpl = Template(text, .{});
    try expectEqualDeep(@as([]const Expression, &.{
        .{ .if_ = comptime try parseIf("if (x)") },
        .{ .literal = "foo" },
        .end,
    }), tmpl.exprs);

    try t.expectEqualStrings("foo", try tmpl.bufPrint(&test_buf, .{ .x = 1 }));
    try t.expectEqualStrings("foo", try tmpl.bufPrint(&test_buf, .{ .x = true }));
    try t.expectEqualStrings("", try tmpl.bufPrint(&test_buf, .{ .x = 0 }));
    try t.expectEqualStrings("", try tmpl.bufPrint(&test_buf, .{ .x = false }));
    var x = struct { x: bool }{ .x = false };
    try t.expectEqualStrings("", try tmpl.bufPrint(&test_buf, x));
}

test "allocPrint" {
    const text =
        \\{{ for(list, 0..) |item, index| }}
        \\  {{index}}={{item}}
        \\  {{ if (index == 0) }}{{% }}{{end}}
        \\{{ end }}
    ;
    const tmpl = Template(text, .{});
    const s = try tmpl.allocPrint(t.allocator, .{ .list = &.{ "a", "b" } });
    defer t.allocator.free(s);
    try t.expectEqualStrings("0=a 1=b", s);
}
