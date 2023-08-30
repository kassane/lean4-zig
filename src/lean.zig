const FlexibleArrayType = std.zig.c_translation.FlexibleArrayType;
pub const __builtin_expect = std.zig.c_builtins.__builtin_expect;

pub extern fn lean_notify_assert(fileName: [*:0]const u8, line: c_int, condition: [*:0]const u8) void;
inline fn assert(src: std.builtin.SourceLocation, cond: bool, msg: [*:0]const u8) void {
    if (!cond) lean_notify_assert(src.file, @intCast(src.line), msg);
}

pub fn lean_is_big_object_tag(tag: u8) callconv(.C) bool {
    return tag == 246 or tag == 247 or tag == 248 or tag == 249;
}

pub const lean_object = extern struct {
    m_rc: c_int,
    m_cs_sz: u16,
    m_other: u8,
    m_tag: u8,
};
pub const LeanPtr = *align(1) lean_object;
pub const lean_obj_arg = LeanPtr;
pub const b_lean_obj_arg = LeanPtr;
pub const u_lean_obj_arg = LeanPtr;
pub const lean_obj_res = LeanPtr;
pub const b_lean_obj_res = LeanPtr;
pub const lean_ctor_object = extern struct {
    m_header: lean_object align(8),
    pub fn m_objs(self: anytype) FlexibleArrayType(@TypeOf(self), LeanPtr) {
        const Intermediate = FlexibleArrayType(@TypeOf(self), u8);
        const ReturnType = FlexibleArrayType(@TypeOf(self), LeanPtr);
        return @as(ReturnType, @ptrCast(@alignCast(@as(Intermediate, @ptrCast(self)) + 8)));
    }
};
pub const lean_array_object = extern struct {
    m_header: lean_object align(8),
    m_size: usize,
    m_capacity: usize,
    pub fn m_data(self: anytype) FlexibleArrayType(@TypeOf(self), LeanPtr) {
        const Intermediate = FlexibleArrayType(@TypeOf(self), u8);
        const ReturnType = FlexibleArrayType(@TypeOf(self), LeanPtr);
        return @as(ReturnType, @ptrCast(@alignCast(@as(Intermediate, @ptrCast(self)) + 24)));
    }
};
pub const lean_sarray_object = extern struct {
    m_header: lean_object align(8),
    m_size: usize,
    m_capacity: usize,
    pub fn m_data(self: anytype) FlexibleArrayType(@TypeOf(self), u8) {
        const Intermediate = FlexibleArrayType(@TypeOf(self), u8);
        const ReturnType = FlexibleArrayType(@TypeOf(self), u8);
        return @as(ReturnType, @ptrCast(@alignCast(@as(Intermediate, @ptrCast(self)) + 24)));
    }
};
pub const lean_string_object = extern struct {
    m_header: lean_object align(8),
    m_size: usize,
    m_capacity: usize,
    m_length: usize,
    pub fn m_data(self: anytype) FlexibleArrayType(@TypeOf(self), u8) {
        const Intermediate = FlexibleArrayType(@TypeOf(self), u8);
        const ReturnType = FlexibleArrayType(@TypeOf(self), u8);
        return @as(ReturnType, @ptrCast(@alignCast(@as(Intermediate, @ptrCast(self)) + 32)));
    }
};
pub const lean_closure_object = extern struct {
    m_header: lean_object align(8),
    m_fun: ?*anyopaque,
    m_arity: u16,
    m_num_fixed: u16,
    pub fn m_objs(self: anytype) FlexibleArrayType(@TypeOf(self), LeanPtr) {
        const Intermediate = FlexibleArrayType(@TypeOf(self), u8);
        const ReturnType = FlexibleArrayType(@TypeOf(self), LeanPtr);
        return @as(ReturnType, @ptrCast(@alignCast(@as(Intermediate, @ptrCast(self)) + 24)));
    }
};
pub const lean_ref_object = extern struct {
    m_header: lean_object,
    m_value: LeanPtr,
};
pub const lean_thunk_object = extern struct {
    m_header: lean_object,
    m_value: LeanPtr, // atomic
    m_closure: LeanPtr, // atomic
};
pub const lean_task_object = extern struct {
    m_header: lean_object,
    m_value: LeanPtr, // atomic
    m_imp: *lean_task_imp,
};
pub const lean_task_imp = extern struct {
    m_closure: LeanPtr,
    m_head_dep: ?*lean_task_object,
    m_next_dep: ?*lean_task_object,
    m_prio: c_uint,
    m_canceled: u8,
    m_keep_alive: u8,
    m_deleted: u8,
};
pub const lean_external_finalize_proc = *const fn (?*anyopaque) callconv(.C) void;
pub const lean_external_foreach_proc = *const fn (?*anyopaque, b_lean_obj_arg) callconv(.C) void;
pub const lean_external_class = extern struct {
    m_finalize: lean_external_finalize_proc,
    m_foreach: lean_external_foreach_proc,
};
pub extern fn lean_register_external_class(lean_external_finalize_proc, lean_external_foreach_proc) *lean_external_class;
pub const lean_external_object = extern struct {
    m_header: lean_object,
    m_class: *lean_external_class,
    m_data: ?*anyopaque,
};
pub fn lean_is_scalar(o: LeanPtr) callconv(.C) bool {
    return @intFromPtr(o) & 1 == 1;
}
pub fn lean_box(n: usize) callconv(.C) LeanPtr {
    return @ptrFromInt((n << 1) | 1);
}
pub fn lean_unbox(o: LeanPtr) callconv(.C) usize {
    return @as(usize, @intCast(@intFromPtr(o))) >> @intCast(1);
}
pub extern fn lean_set_exit_on_panic(flag: bool) void;
pub extern fn lean_set_panic_messages(flag: bool) void;
pub extern fn lean_panic_fn(default_val: LeanPtr, msg: LeanPtr) LeanPtr;
pub extern fn lean_internal_panic(msg: [*:0]const u8) noreturn;
pub extern fn lean_internal_panic_out_of_memory(...) noreturn;
pub extern fn lean_internal_panic_unreachable(...) noreturn;
pub extern fn lean_internal_panic_rc_overflow(...) noreturn;
pub fn lean_align(v: usize, a: usize) callconv(.C) usize {
    return ((v / a) *% a) +% (a *% @as(usize, @intFromBool((v % a) != 0)));
}
pub fn lean_get_slot_idx(sz: c_uint) callconv(.C) c_uint {
    assert(@src(), sz > 0, "sz > 0");
    assert(@src(), lean_align(sz, LEAN_OBJECT_SIZE_DELTA) == sz, "lean_align(sz, LEAN_OBJECT_SIZE_DELTA) == sz");
    return sz / LEAN_OBJECT_SIZE_DELTA - 1;
}
pub extern fn lean_alloc_small(sz: c_uint, slot_idx: c_uint) ?*anyopaque;
pub extern fn lean_free_small(p: ?*anyopaque) void;
pub extern fn lean_small_mem_size(p: ?*anyopaque) c_uint;
pub extern fn lean_inc_heartbeat(...) void;
pub extern fn malloc(c_ulong) ?*anyopaque;
pub fn lean_alloc_small_object(sz: c_uint) callconv(.C) LeanPtr {
    sz = @as(c_uint, @bitCast(@as(c_uint, @truncate(lean_align(@as(usize, @bitCast(@as(c_ulong, sz))), @as(usize, @bitCast(@as(c_long, @as(c_int, 8)))))))));
    var slot_idx: c_uint = lean_get_slot_idx(sz);
    assert(@src(), sz <= LEAN_MAX_SMALL_OBJECT_SIZE, "sz <= LEAN_MAX_SMALL_OBJECT_SIZE");
    return @as(LeanPtr, @ptrCast(lean_alloc_small(sz, slot_idx)));
}
pub fn lean_alloc_ctor_memory(sz: c_uint) callconv(.C) LeanPtr {
    var sz1: c_uint = @as(c_uint, @bitCast(@as(c_uint, @truncate(lean_align(@as(usize, @bitCast(@as(c_ulong, sz))), @as(usize, @bitCast(@as(c_long, @as(c_int, 8)))))))));
    var slot_idx: c_uint = lean_get_slot_idx(sz1);
    assert(@src(), sz1 <= LEAN_MAX_SMALL_OBJECT_SIZE, "sz1 <= LEAN_MAX_SMALL_OBJECT_SIZE");
    var r: LeanPtr = @ptrCast(lean_alloc_small(sz1, slot_idx));
    if (sz1 > sz) {
        var end: [*]usize = @as([*]usize, @ptrCast(@alignCast(@as([*]u8, @ptrCast(r)) + sz1)));
        (end - 1)[0] = 0;
    }
    return r;
}
pub fn lean_small_object_size(o: LeanPtr) callconv(.C) c_uint {
    return lean_small_mem_size(@as(?*anyopaque, @ptrCast(o)));
}
pub extern fn free(?*anyopaque) void;
pub fn lean_free_small_object(o: LeanPtr) callconv(.C) void {
    lean_free_small(@as(?*anyopaque, @ptrCast(o)));
}
pub extern fn lean_alloc_object(sz: usize) LeanPtr;
pub extern fn lean_free_object(o: LeanPtr) void;
pub fn lean_ptr_tag(o: LeanPtr) callconv(.C) u8 {
    return @as(u8, @bitCast(@as(u8, @truncate(o.*.m_tag))));
}
pub fn lean_ptr_other(o: LeanPtr) callconv(.C) c_uint {
    return o.*.m_other;
}
pub extern fn lean_object_byte_size(o: LeanPtr) usize;
pub fn lean_is_mt(o: LeanPtr) callconv(.C) bool {
    return o.*.m_rc < 0;
}
pub fn lean_is_st(o: LeanPtr) callconv(.C) bool {
    return o.*.m_rc > 0;
}
pub fn lean_is_persistent(o: LeanPtr) callconv(.C) bool {
    return o.*.m_rc == 0;
}
pub fn lean_has_rc(o: LeanPtr) callconv(.C) bool {
    return o.*.m_rc != 0;
}
pub fn lean_get_rc_mt_addr(o: LeanPtr) callconv(.C) *c_int { // atomic
    return &o.*.m_rc;
}
pub extern fn lean_inc_ref_cold(o: LeanPtr) void;
pub extern fn lean_inc_ref_n_cold(o: LeanPtr, n: c_uint) void;
pub fn lean_inc_ref(o: LeanPtr) callconv(.C) void {
    if (__builtin_expect(@as(c_long, @intFromBool(lean_is_st(o))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        o.*.m_rc += 1;
    } else if (o.*.m_rc != 0) {
        lean_inc_ref_cold(o);
    }
}
pub fn lean_inc_ref_n(o: LeanPtr, n: usize) callconv(.C) void {
    if (__builtin_expect(@as(c_long, @intFromBool(lean_is_st(o))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        o.*.m_rc += @as(c_int, @bitCast(@as(c_uint, @truncate(n))));
    } else if (o.*.m_rc != 0) {
        lean_inc_ref_n_cold(o, @as(c_uint, @bitCast(@as(c_uint, @truncate(n)))));
    }
}
pub extern fn lean_dec_ref_cold(o: LeanPtr) void;
pub fn lean_dec_ref(o: LeanPtr) callconv(.C) void {
    if (__builtin_expect(@as(c_long, @intFromBool(o.*.m_rc > @as(c_int, 1))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        o.*.m_rc -= 1;
    } else if (o.*.m_rc != 0) {
        lean_dec_ref_cold(o);
    }
}
pub fn lean_inc(o: LeanPtr) callconv(.C) void {
    if (!lean_is_scalar(o)) {
        lean_inc_ref(o);
    }
}
pub fn lean_inc_n(o: LeanPtr, n: usize) callconv(.C) void {
    if (!lean_is_scalar(o)) {
        lean_inc_ref_n(o, n);
    }
}
pub fn lean_dec(o: LeanPtr) callconv(.C) void {
    if (!lean_is_scalar(o)) {
        lean_dec_ref(o);
    }
}
pub extern fn lean_dealloc(o: LeanPtr) void;
pub fn lean_is_ctor(o: LeanPtr) callconv(.C) bool {
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(o)))) <= @as(c_int, 244);
}
pub fn lean_is_closure(o: LeanPtr) callconv(.C) bool {
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(o)))) == @as(c_int, 245);
}
pub fn lean_is_array(o: LeanPtr) callconv(.C) bool {
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(o)))) == @as(c_int, 246);
}
pub fn lean_is_sarray(o: LeanPtr) callconv(.C) bool {
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(o)))) == @as(c_int, 248);
}
pub fn lean_is_string(o: LeanPtr) callconv(.C) bool {
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(o)))) == @as(c_int, 249);
}
pub fn lean_is_mpz(o: LeanPtr) callconv(.C) bool {
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(o)))) == @as(c_int, 250);
}
pub fn lean_is_thunk(o: LeanPtr) callconv(.C) bool {
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(o)))) == @as(c_int, 251);
}
pub fn lean_is_task(o: LeanPtr) callconv(.C) bool {
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(o)))) == @as(c_int, 252);
}
pub fn lean_is_external(o: LeanPtr) callconv(.C) bool {
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(o)))) == @as(c_int, 254);
}
pub fn lean_is_ref(o: LeanPtr) callconv(.C) bool {
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(o)))) == @as(c_int, 253);
}
pub fn lean_obj_tag(o: LeanPtr) callconv(.C) c_uint {
    if (lean_is_scalar(o)) return @as(c_uint, @bitCast(@as(c_uint, @truncate(lean_unbox(o))))) else return @as(c_uint, @bitCast(@as(c_uint, lean_ptr_tag(o))));
    return 0;
}
pub fn lean_to_ctor(o: LeanPtr) callconv(.C) *lean_ctor_object {
    assert(@src(), lean_is_ctor(o), "lean_is_ctor(o)");
    return @as(*lean_ctor_object, @ptrCast(@alignCast(o)));
}
pub fn lean_to_closure(o: LeanPtr) callconv(.C) *lean_closure_object {
    assert(@src(), lean_is_closure(o), "lean_is_closure(o)");
    return @as(*lean_closure_object, @ptrCast(@alignCast(o)));
}
pub fn lean_to_array(o: LeanPtr) callconv(.C) ?*lean_array_object {
    assert(@src(), lean_is_array(o), "lean_is_array(o)");
    return @as(?*lean_array_object, @ptrCast(@alignCast(o)));
}
pub fn lean_to_sarray(o: LeanPtr) callconv(.C) ?*lean_sarray_object {
    assert(@src(), lean_is_sarray(o), "lean_is_sarray(o)");
    return @as(?*lean_sarray_object, @ptrCast(@alignCast(o)));
}
pub fn lean_to_string(o: LeanPtr) callconv(.C) *lean_string_object {
    assert(@src(), lean_is_string(o), "lean_is_string(o)");
    return @as(*lean_string_object, @ptrCast(@alignCast(o)));
}
pub fn lean_to_thunk(o: LeanPtr) callconv(.C) *lean_thunk_object {
    assert(@src(), lean_is_thunk(o), "lean_is_thunk(o)");
    return @as(*lean_thunk_object, @ptrCast(@alignCast(o)));
}
pub fn lean_to_task(o: LeanPtr) callconv(.C) *lean_task_object {
    assert(@src(), lean_is_task(o), "lean_is_task(o)");
    return @as(*lean_task_object, @ptrCast(@alignCast(o)));
}
pub fn lean_to_ref(o: LeanPtr) callconv(.C) *lean_ref_object {
    assert(@src(), lean_is_ref(o), "lean_is_ref(o)");
    return @as(*lean_ref_object, @ptrCast(@alignCast(o)));
}
pub fn lean_to_external(o: LeanPtr) callconv(.C) *lean_external_object {
    assert(@src(), lean_is_external(o), "lean_is_external(o)");
    return @as(*lean_external_object, @ptrCast(@alignCast(o)));
}
pub fn lean_is_exclusive(o: LeanPtr) callconv(.C) bool {
    if (LEAN_LIKELY(lean_is_st(o))) {
        return o.*.m_rc == 1;
    } else {
        return false;
    }
}
pub fn lean_is_shared(o: LeanPtr) callconv(.C) bool {
    if (LEAN_LIKELY(lean_is_st(o))) {
        return o.*.m_rc > 1;
    } else {
        return false;
    }
}
pub extern fn lean_mark_mt(o: LeanPtr) void;
pub extern fn lean_mark_persistent(o: LeanPtr) void;
pub fn lean_set_st_header(o: LeanPtr, tag: c_uint, other: c_uint) callconv(.C) void {
    o.*.m_rc = 1;
    o.*.m_tag = @intCast(tag);
    o.*.m_other = @intCast(other);
    o.*.m_cs_sz = 0;
}
pub fn lean_set_non_heap_header(o: LeanPtr, sz: usize, tag: c_uint, other: c_uint) callconv(.C) void {
    assert(@src(), sz > 0, "sz > 0");
    assert(@src(), sz < (1 << 16), "sz < (1ull << 16)");
    assert(@src(), sz == 1 || !lean_is_big_object_tag(tag), "sz == 1 || !lean_is_big_object_tag(tag)");
    o.*.m_rc = 0;
    o.*.m_tag = tag;
    o.*.m_other = other;
    o.*.m_cs_sz = @truncate(sz);
}
pub fn lean_set_non_heap_header_for_big(o: LeanPtr, tag: c_uint, other: c_uint) callconv(.C) void {
    lean_set_non_heap_header(o, @as(usize, @bitCast(@as(c_long, @as(c_int, 1)))), tag, other);
}
pub fn lean_ctor_num_objs(o: LeanPtr) callconv(.C) c_uint {
    assert(@src(), lean_is_ctor(o), "lean_is_ctor(o)");
    return lean_ptr_other(o);
}
pub fn lean_ctor_obj_cptr(o: LeanPtr) callconv(.C) [*c]LeanPtr {
    assert(@src(), lean_is_ctor(o), "lean_is_ctor(o)");
    return lean_to_ctor(o).*.m_objs();
}
pub fn lean_ctor_scalar_cptr(o: LeanPtr) callconv(.C) [*c]u8 {
    assert(@src(), lean_is_ctor(o), "lean_is_ctor(o)");
    return @as([*c]u8, @ptrCast(@alignCast(lean_ctor_obj_cptr(o) + lean_ctor_num_objs(o))));
}
pub fn lean_alloc_ctor(tag: c_uint, num_objs: c_uint, scalar_sz: c_uint) callconv(.C) LeanPtr {
    assert(@src(), tag <= LeanMaxCtorTag and num_objs < LEAN_MAX_CTOR_FIELDS and scalar_sz < LEAN_MAX_CTOR_SCALARS_SIZE, "tag <= LeanMaxCtorTag && num_objs < LEAN_MAX_CTOR_FIELDS && scalar_sz < LEAN_MAX_CTOR_SCALARS_SIZE");
    var o: LeanPtr = lean_alloc_ctor_memory(@as(c_uint, @bitCast(@as(c_uint, @truncate((@sizeOf(lean_ctor_object) +% (@sizeOf(*anyopaque) *% @as(c_ulong, @bitCast(@as(c_ulong, num_objs))))) +% @as(c_ulong, @bitCast(@as(c_ulong, scalar_sz))))))));
    lean_set_st_header(o, tag, num_objs);
    return o;
}
pub fn lean_ctor_get(o: b_lean_obj_arg, i: c_uint) callconv(.C) b_lean_obj_res {
    assert(@src(), i < lean_ctor_num_objs(o), "i < lean_ctor_num_objs(o)");
    return lean_ctor_obj_cptr(o)[i];
}
pub fn lean_ctor_set(o: b_lean_obj_arg, i: c_uint, v: lean_obj_arg) callconv(.C) void {
    assert(@src(), i < lean_ctor_num_objs(o), "i < lean_ctor_num_objs(o)");
    lean_ctor_obj_cptr(o)[i] = v;
}
pub fn lean_ctor_set_tag(o: b_lean_obj_arg, new_tag: u8) callconv(.C) void {
    assert(@src(), new_tag <= LeanMaxCtorTag, "new_tag <= LeanMaxCtorTag");
    o.*.m_tag = @as(c_uint, @bitCast(@as(c_uint, new_tag)));
}
pub fn lean_ctor_release(o: b_lean_obj_arg, i: c_uint) callconv(.C) void {
    assert(@src(), i < lean_ctor_num_objs(o), "i < lean_ctor_num_objs(o)");
    var objs: [*c]LeanPtr = lean_ctor_obj_cptr(o);
    lean_dec(objs[i]);
    objs[i] = lean_box(0);
}
pub fn lean_ctor_get_usize(o: b_lean_obj_arg, i: c_uint) callconv(.C) usize {
    assert(@src(), i >= lean_ctor_num_objs(o), "i >= lean_ctor_num_objs(o)");
    return @as([*c]usize, @ptrCast(@alignCast(lean_ctor_obj_cptr(o) + i))).*;
}
pub fn lean_ctor_get_uint8(o: b_lean_obj_arg, offset: c_uint) callconv(.C) u8 {
    assert(@src(), offset >= lean_ctor_num_objs(o) * @sizeOf(*anyopaque), "offset >= lean_ctor_num_objs(o) * sizeof(void*)");
    return (@as([*c]u8, @ptrCast(@alignCast(lean_ctor_obj_cptr(o)))) + offset).*;
}
pub fn lean_ctor_get_uint16(o: b_lean_obj_arg, offset: c_uint) callconv(.C) u16 {
    assert(@src(), offset >= lean_ctor_num_objs(o) * @sizeOf(*anyopaque), "offset >= lean_ctor_num_objs(o) * sizeof(void*)");
    return @as([*c]u16, @ptrCast(@alignCast(@as([*c]u8, @ptrCast(@alignCast(lean_ctor_obj_cptr(o)))) + offset))).*;
}
pub fn lean_ctor_get_uint32(o: b_lean_obj_arg, offset: c_uint) callconv(.C) u32 {
    assert(@src(), offset >= lean_ctor_num_objs(o) * @sizeOf(*anyopaque), "offset >= lean_ctor_num_objs(o) * sizeof(void*)");
    return @as([*c]u32, @ptrCast(@alignCast(@as([*c]u8, @ptrCast(@alignCast(lean_ctor_obj_cptr(o)))) + offset))).*;
}
pub fn lean_ctor_get_uint64(o: b_lean_obj_arg, offset: c_uint) callconv(.C) u64 {
    assert(@src(), offset >= lean_ctor_num_objs(o) * @sizeOf(*anyopaque), "offset >= lean_ctor_num_objs(o) * sizeof(void*)");
    return @as([*c]u64, @ptrCast(@alignCast(@as([*c]u8, @ptrCast(@alignCast(lean_ctor_obj_cptr(o)))) + offset))).*;
}
pub fn lean_ctor_get_float(o: b_lean_obj_arg, offset: c_uint) callconv(.C) f64 {
    assert(@src(), offset >= lean_ctor_num_objs(o) * @sizeOf(*anyopaque), "offset >= lean_ctor_num_objs(o) * sizeof(void*)");
    return @as([*c]f64, @ptrCast(@alignCast(@as([*c]u8, @ptrCast(@alignCast(lean_ctor_obj_cptr(o)))) + offset))).*;
}
pub fn lean_ctor_set_usize(o: b_lean_obj_arg, i: c_uint, v: usize) callconv(.C) void {
    assert(@src(), i >= lean_ctor_num_objs(o), "i >= lean_ctor_num_objs(o)");
    @as([*c]usize, @ptrCast(@alignCast(lean_ctor_obj_cptr(o) + i))).* = v;
}
pub fn lean_ctor_set_uint8(o: b_lean_obj_arg, offset: c_uint, v: u8) callconv(.C) void {
    assert(@src(), offset >= lean_ctor_num_objs(o) * @sizeOf(*anyopaque), "offset >= lean_ctor_num_objs(o) * sizeof(void*)");
    (@as([*c]u8, @ptrCast(@alignCast(lean_ctor_obj_cptr(o)))) + offset).* = v;
}
pub fn lean_ctor_set_uint16(o: b_lean_obj_arg, offset: c_uint, v: u16) callconv(.C) void {
    assert(@src(), offset >= lean_ctor_num_objs(o) * @sizeOf(*anyopaque), "offset >= lean_ctor_num_objs(o) * sizeof(void*)");
    @as([*c]u16, @ptrCast(@alignCast(@as([*c]u8, @ptrCast(@alignCast(lean_ctor_obj_cptr(o)))) + offset))).* = v;
}
pub fn lean_ctor_set_uint32(o: b_lean_obj_arg, offset: c_uint, v: u32) callconv(.C) void {
    assert(@src(), offset >= lean_ctor_num_objs(o) * @sizeOf(*anyopaque), "offset >= lean_ctor_num_objs(o) * sizeof(void*)");
    @as([*c]u32, @ptrCast(@alignCast(@as([*c]u8, @ptrCast(@alignCast(lean_ctor_obj_cptr(o)))) + offset))).* = v;
}
pub fn lean_ctor_set_uint64(o: b_lean_obj_arg, offset: c_uint, v: u64) callconv(.C) void {
    assert(@src(), offset >= lean_ctor_num_objs(o) * @sizeOf(*anyopaque), "offset >= lean_ctor_num_objs(o) * sizeof(void*)");
    @as([*c]u64, @ptrCast(@alignCast(@as([*c]u8, @ptrCast(@alignCast(lean_ctor_obj_cptr(o)))) + offset))).* = v;
}
pub fn lean_ctor_set_float(o: b_lean_obj_arg, offset: c_uint, v: f64) callconv(.C) void {
    assert(@src(), offset >= lean_ctor_num_objs(o) * @sizeOf(*anyopaque), "offset >= lean_ctor_num_objs(o) * sizeof(void*)");
    @as([*c]f64, @ptrCast(@alignCast(@as([*c]u8, @ptrCast(@alignCast(lean_ctor_obj_cptr(o)))) + offset))).* = v;
}
pub fn lean_closure_fun(o: LeanPtr) callconv(.C) ?*anyopaque {
    return lean_to_closure(o).*.m_fun;
}
pub fn lean_closure_arity(o: LeanPtr) callconv(.C) c_uint {
    return @as(c_uint, @bitCast(@as(c_uint, lean_to_closure(o).*.m_arity)));
}
pub fn lean_closure_num_fixed(o: LeanPtr) callconv(.C) c_uint {
    return @as(c_uint, @bitCast(@as(c_uint, lean_to_closure(o).*.m_num_fixed)));
}
pub fn lean_closure_cptr(o: LeanPtr) callconv(.C) [*c]LeanPtr {
    return lean_to_closure(o).*.m_objs();
}
pub fn lean_alloc_closure(fun: ?*anyopaque, arity: c_uint, num_fixed: c_uint) callconv(.C) lean_obj_res {
    assert(@src(), arity > 0, "arity > 0");
    assert(@src(), num_fixed < arity, "num_fixed < arity");
    var o: *lean_closure_object = @as(*lean_closure_object, @ptrCast(@alignCast(lean_alloc_small_object(@as(c_uint, @bitCast(@as(c_uint, @truncate(@sizeOf(lean_closure_object) +% (@sizeOf(*anyopaque) *% @as(c_ulong, @bitCast(@as(c_ulong, num_fixed))))))))))));
    lean_set_st_header(@as(LeanPtr, @ptrCast(o)), @as(c_uint, @bitCast(@as(c_int, 245))), @as(c_uint, @bitCast(0)));
    o.*.m_fun = fun;
    o.*.m_arity = @as(u16, @bitCast(@as(c_ushort, @truncate(arity))));
    o.*.m_num_fixed = @as(u16, @bitCast(@as(c_ushort, @truncate(num_fixed))));
    return @as(LeanPtr, @ptrCast(o));
}
pub fn lean_closure_get(o: b_lean_obj_arg, i: c_uint) callconv(.C) b_lean_obj_res {
    assert(@src(), i < lean_closure_num_fixed(o), "i < lean_closure_num_fixed(o)");
    return lean_to_closure(o).*.m_objs()[i];
}
pub fn lean_closure_set(o: u_lean_obj_arg, i: c_uint, a: lean_obj_arg) callconv(.C) void {
    assert(@src(), i < lean_closure_num_fixed(o), "i < lean_closure_num_fixed(o)");
    lean_to_closure(o).*.m_objs()[i] = a;
}
pub extern fn lean_apply_1(f: LeanPtr, a1: LeanPtr) LeanPtr;
pub extern fn lean_apply_2(f: LeanPtr, a1: LeanPtr, a2: LeanPtr) LeanPtr;
pub extern fn lean_apply_3(f: LeanPtr, a1: LeanPtr, a2: LeanPtr, a3: LeanPtr) LeanPtr;
pub extern fn lean_apply_4(f: LeanPtr, a1: LeanPtr, a2: LeanPtr, a3: LeanPtr, a4: LeanPtr) LeanPtr;
pub extern fn lean_apply_5(f: LeanPtr, a1: LeanPtr, a2: LeanPtr, a3: LeanPtr, a4: LeanPtr, a5: LeanPtr) LeanPtr;
pub extern fn lean_apply_6(f: LeanPtr, a1: LeanPtr, a2: LeanPtr, a3: LeanPtr, a4: LeanPtr, a5: LeanPtr, a6: LeanPtr) LeanPtr;
pub extern fn lean_apply_7(f: LeanPtr, a1: LeanPtr, a2: LeanPtr, a3: LeanPtr, a4: LeanPtr, a5: LeanPtr, a6: LeanPtr, a7: LeanPtr) LeanPtr;
pub extern fn lean_apply_8(f: LeanPtr, a1: LeanPtr, a2: LeanPtr, a3: LeanPtr, a4: LeanPtr, a5: LeanPtr, a6: LeanPtr, a7: LeanPtr, a8: LeanPtr) LeanPtr;
pub extern fn lean_apply_9(f: LeanPtr, a1: LeanPtr, a2: LeanPtr, a3: LeanPtr, a4: LeanPtr, a5: LeanPtr, a6: LeanPtr, a7: LeanPtr, a8: LeanPtr, a9: LeanPtr) LeanPtr;
pub extern fn lean_apply_10(f: LeanPtr, a1: LeanPtr, a2: LeanPtr, a3: LeanPtr, a4: LeanPtr, a5: LeanPtr, a6: LeanPtr, a7: LeanPtr, a8: LeanPtr, a9: LeanPtr, a10: LeanPtr) LeanPtr;
pub extern fn lean_apply_11(f: LeanPtr, a1: LeanPtr, a2: LeanPtr, a3: LeanPtr, a4: LeanPtr, a5: LeanPtr, a6: LeanPtr, a7: LeanPtr, a8: LeanPtr, a9: LeanPtr, a10: LeanPtr, a11: LeanPtr) LeanPtr;
pub extern fn lean_apply_12(f: LeanPtr, a1: LeanPtr, a2: LeanPtr, a3: LeanPtr, a4: LeanPtr, a5: LeanPtr, a6: LeanPtr, a7: LeanPtr, a8: LeanPtr, a9: LeanPtr, a10: LeanPtr, a11: LeanPtr, a12: LeanPtr) LeanPtr;
pub extern fn lean_apply_13(f: LeanPtr, a1: LeanPtr, a2: LeanPtr, a3: LeanPtr, a4: LeanPtr, a5: LeanPtr, a6: LeanPtr, a7: LeanPtr, a8: LeanPtr, a9: LeanPtr, a10: LeanPtr, a11: LeanPtr, a12: LeanPtr, a13: LeanPtr) LeanPtr;
pub extern fn lean_apply_14(f: LeanPtr, a1: LeanPtr, a2: LeanPtr, a3: LeanPtr, a4: LeanPtr, a5: LeanPtr, a6: LeanPtr, a7: LeanPtr, a8: LeanPtr, a9: LeanPtr, a10: LeanPtr, a11: LeanPtr, a12: LeanPtr, a13: LeanPtr, a14: LeanPtr) LeanPtr;
pub extern fn lean_apply_15(f: LeanPtr, a1: LeanPtr, a2: LeanPtr, a3: LeanPtr, a4: LeanPtr, a5: LeanPtr, a6: LeanPtr, a7: LeanPtr, a8: LeanPtr, a9: LeanPtr, a10: LeanPtr, a11: LeanPtr, a12: LeanPtr, a13: LeanPtr, a14: LeanPtr, a15: LeanPtr) LeanPtr;
pub extern fn lean_apply_16(f: LeanPtr, a1: LeanPtr, a2: LeanPtr, a3: LeanPtr, a4: LeanPtr, a5: LeanPtr, a6: LeanPtr, a7: LeanPtr, a8: LeanPtr, a9: LeanPtr, a10: LeanPtr, a11: LeanPtr, a12: LeanPtr, a13: LeanPtr, a14: LeanPtr, a15: LeanPtr, a16: LeanPtr) LeanPtr;
pub extern fn lean_apply_n(f: LeanPtr, n: c_uint, args: [*c]LeanPtr) LeanPtr;
pub extern fn lean_apply_m(f: LeanPtr, n: c_uint, args: [*c]LeanPtr) LeanPtr;
pub fn lean_alloc_array(size: usize, capacity: usize) callconv(.C) lean_obj_res {
    var o: ?*lean_array_object = @as(?*lean_array_object, @ptrCast(@alignCast(lean_alloc_object(@sizeOf(lean_array_object) +% (@sizeOf(*anyopaque) *% capacity)))));
    lean_set_st_header(@as(LeanPtr, @ptrCast(o)), @as(c_uint, @bitCast(@as(c_int, 246))), @as(c_uint, @bitCast(0)));
    o.*.m_size = size;
    o.*.m_capacity = capacity;
    return @as(LeanPtr, @ptrCast(o));
}
pub fn lean_array_size(o: b_lean_obj_arg) callconv(.C) usize {
    return lean_to_array(o).*.m_size;
}
pub fn lean_array_capacity(o: b_lean_obj_arg) callconv(.C) usize {
    return lean_to_array(o).*.m_capacity;
}
pub fn lean_array_byte_size(o: LeanPtr) callconv(.C) usize {
    return @sizeOf(lean_array_object) +% (@sizeOf(*anyopaque) *% lean_array_capacity(o));
}
pub fn lean_array_cptr(o: LeanPtr) callconv(.C) [*c]LeanPtr {
    return lean_to_array(o).*.m_data();
}
pub fn lean_array_set_size(o: u_lean_obj_arg, sz: usize) callconv(.C) void {
    assert(@src(), lean_is_array(o), "lean_is_array(o)");
    assert(@src(), lean_is_exclusive(o), "lean_is_exclusive(o)");
    assert(@src(), sz <= lean_array_capacity(o), "sz <= lean_array_capacity(o)");
    lean_to_array(o).*.m_size = sz;
}
pub fn lean_array_get_core(o: b_lean_obj_arg, i: usize) callconv(.C) b_lean_obj_res {
    assert(@src(), i < lean_array_size(o), "i < lean_array_size(o)");
    return lean_to_array(o).*.m_data()[i];
}
pub fn lean_array_set_core(o: u_lean_obj_arg, i: usize, v: lean_obj_arg) callconv(.C) void {
    assert(@src(), !lean_has_rc(o) || lean_is_exclusive(o), "!lean_has_rc(o) || lean_is_exclusive(o)");
    assert(@src(), i < lean_array_size(o), "i < lean_array_size(o)");
    lean_to_array(o).*.m_data()[i] = v;
}
pub extern fn lean_array_mk(l: lean_obj_arg) LeanPtr;
pub extern fn lean_array_data(a: lean_obj_arg) LeanPtr;
pub fn lean_array_sz(a: lean_obj_arg) callconv(.C) LeanPtr {
    var r: LeanPtr = lean_box(lean_array_size(a));
    lean_dec(a);
    return r;
}
pub fn lean_array_get_size(a: b_lean_obj_arg) callconv(.C) LeanPtr {
    return lean_box(lean_array_size(a));
}
pub fn lean_mk_empty_array() callconv(.C) LeanPtr {
    return lean_alloc_array(0, 0);
}
pub fn lean_mk_empty_array_with_capacity(capacity: b_lean_obj_arg) callconv(.C) LeanPtr {
    if (!lean_is_scalar(capacity)) {
        lean_internal_panic_out_of_memory();
    }
    return lean_alloc_array(0, lean_unbox(capacity));
}
pub fn lean_array_uget(a: b_lean_obj_arg, i: usize) callconv(.C) LeanPtr {
    var r: LeanPtr = lean_array_get_core(a, i);
    lean_inc(r);
    return r;
}
pub fn lean_array_fget(a: b_lean_obj_arg, i: b_lean_obj_arg) callconv(.C) lean_obj_res {
    return lean_array_uget(a, lean_unbox(i));
}
pub extern fn lean_array_get_panic(def_val: lean_obj_arg) lean_obj_res;
pub fn lean_array_get(def_val: lean_obj_arg, a: b_lean_obj_arg, i: b_lean_obj_arg) callconv(.C) LeanPtr {
    if (lean_is_scalar(i)) {
        var idx: usize = lean_unbox(i);
        if (idx < lean_array_size(a)) {
            lean_dec(def_val);
            return lean_array_uget(a, idx);
        }
    }
    return lean_array_get_panic(def_val);
}
pub extern fn lean_copy_expand_array(a: lean_obj_arg, expand: bool) lean_obj_res;
pub fn lean_copy_array(a: lean_obj_arg) callconv(.C) lean_obj_res {
    return lean_copy_expand_array(a, 0 != 0);
}
pub fn lean_ensure_exclusive_array(a: lean_obj_arg) callconv(.C) lean_obj_res {
    if (lean_is_exclusive(a)) return a;
    return lean_copy_array(a);
}
pub fn lean_array_uset(a: lean_obj_arg, i: usize, v: lean_obj_arg) callconv(.C) LeanPtr {
    var r: LeanPtr = lean_ensure_exclusive_array(a);
    var it: [*c]LeanPtr = lean_array_cptr(r) + i;
    lean_dec(it.*);
    it.* = v;
    return r;
}
pub fn lean_array_fset(a: lean_obj_arg, i: b_lean_obj_arg, v: lean_obj_arg) callconv(.C) LeanPtr {
    return lean_array_uset(a, lean_unbox(i), v);
}
pub extern fn lean_array_set_panic(a: lean_obj_arg, v: lean_obj_arg) lean_obj_res;
pub fn lean_array_set(a: lean_obj_arg, i: b_lean_obj_arg, v: lean_obj_arg) callconv(.C) LeanPtr {
    if (lean_is_scalar(i)) {
        var idx: usize = lean_unbox(i);
        if (idx < lean_array_size(a)) return lean_array_uset(a, idx, v);
    }
    return lean_array_set_panic(a, v);
}
pub fn lean_array_pop(a: lean_obj_arg) callconv(.C) LeanPtr {
    var r: LeanPtr = lean_ensure_exclusive_array(a);
    var sz: usize = lean_to_array(r).*.m_size;
    var last: [*c]LeanPtr = undefined;
    if (sz == 0) return r;
    sz -%= 1;
    last = lean_array_cptr(r) + sz;
    lean_to_array(r).*.m_size = sz;
    lean_dec(last.*);
    return r;
}
pub fn lean_array_uswap(a: lean_obj_arg, i: usize, j: usize) callconv(.C) LeanPtr {
    var r: LeanPtr = lean_ensure_exclusive_array(a);
    var it: [*c]LeanPtr = lean_array_cptr(r);
    var v1: LeanPtr = it[i];
    it[i] = it[j];
    it[j] = v1;
    return r;
}
pub fn lean_array_fswap(a: lean_obj_arg, i: b_lean_obj_arg, j: b_lean_obj_arg) callconv(.C) LeanPtr {
    return lean_array_uswap(a, lean_unbox(i), lean_unbox(j));
}
pub fn lean_array_swap(a: lean_obj_arg, i: b_lean_obj_arg, j: b_lean_obj_arg) callconv(.C) LeanPtr {
    if (!lean_is_scalar(i) or !lean_is_scalar(j)) return a;
    var ui: usize = lean_unbox(i);
    var uj: usize = lean_unbox(j);
    var sz: usize = lean_to_array(a).*.m_size;
    if ((ui >= sz) or (uj >= sz)) return a;
    return lean_array_uswap(a, ui, uj);
}
pub extern fn lean_array_push(a: lean_obj_arg, v: lean_obj_arg) LeanPtr;
pub extern fn lean_mk_array(n: lean_obj_arg, v: lean_obj_arg) LeanPtr;
pub fn lean_alloc_sarray(elem_size: c_uint, size: usize, capacity: usize) callconv(.C) lean_obj_res {
    var o: ?*lean_sarray_object = @as(?*lean_sarray_object, @ptrCast(@alignCast(lean_alloc_object(@sizeOf(lean_sarray_object) +% (@as(usize, @bitCast(@as(c_ulong, elem_size))) *% capacity)))));
    lean_set_st_header(@as(LeanPtr, @ptrCast(o)), @as(c_uint, @bitCast(@as(c_int, 248))), elem_size);
    o.*.m_size = size;
    o.*.m_capacity = capacity;
    return @as(LeanPtr, @ptrCast(o));
}
pub fn lean_sarray_elem_size(o: LeanPtr) callconv(.C) c_uint {
    assert(@src(), lean_is_sarray(o), "lean_is_sarray(o)");
    return lean_ptr_other(o);
}
pub fn lean_sarray_capacity(o: LeanPtr) callconv(.C) usize {
    return lean_to_sarray(o).*.m_capacity;
}
pub fn lean_sarray_byte_size(o: LeanPtr) callconv(.C) usize {
    return @sizeOf(lean_sarray_object) +% (@as(usize, @bitCast(@as(c_ulong, lean_sarray_elem_size(o)))) *% lean_sarray_capacity(o));
}
pub fn lean_sarray_size(o: b_lean_obj_arg) callconv(.C) usize {
    return lean_to_sarray(o).*.m_size;
}
pub fn lean_sarray_set_size(o: u_lean_obj_arg, sz: usize) callconv(.C) void {
    assert(@src(), lean_is_exclusive(o), "lean_is_exclusive(o)");
    assert(@src(), sz <= lean_sarray_capacity(o), "sz <= lean_sarray_capacity(o)");
    lean_to_sarray(o).*.m_size = sz;
}
pub fn lean_sarray_cptr(o: LeanPtr) callconv(.C) [*c]u8 {
    return lean_to_sarray(o).*.m_data();
}
pub extern fn lean_byte_array_mk(a: lean_obj_arg) lean_obj_res;
pub extern fn lean_byte_array_data(a: lean_obj_arg) lean_obj_res;
pub extern fn lean_copy_byte_array(a: lean_obj_arg) lean_obj_res;
pub extern fn lean_byte_array_hash(a: b_lean_obj_arg) u64;
pub fn lean_mk_empty_byte_array(capacity: b_lean_obj_arg) callconv(.C) lean_obj_res {
    if (!lean_is_scalar(capacity)) {
        lean_internal_panic_out_of_memory();
    }
    return lean_alloc_sarray(@as(c_uint, @bitCast(@as(c_int, 1))), 0, lean_unbox(capacity));
}
pub fn lean_byte_array_size(a: b_lean_obj_arg) callconv(.C) lean_obj_res {
    return lean_box(lean_sarray_size(a));
}
pub fn lean_byte_array_uget(a: b_lean_obj_arg, i: usize) callconv(.C) u8 {
    assert(@src(), i < lean_sarray_size(a), "i < lean_sarray_size(a)");
    return lean_sarray_cptr(a)[i];
}
pub fn lean_byte_array_get(a: b_lean_obj_arg, i: b_lean_obj_arg) callconv(.C) u8 {
    if (lean_is_scalar(i)) {
        var idx: usize = lean_unbox(i);
        return @as(u8, @bitCast(@as(i8, @truncate(if (idx < lean_sarray_size(a)) @as(c_int, @bitCast(@as(c_uint, lean_byte_array_uget(a, idx)))) else 0))));
    } else {
        return 0;
    }
    return std.mem.zeroes(u8);
}
pub fn lean_byte_array_fget(a: b_lean_obj_arg, i: b_lean_obj_arg) callconv(.C) u8 {
    return lean_byte_array_uget(a, lean_unbox(i));
}
pub extern fn lean_byte_array_push(a: lean_obj_arg, b: u8) lean_obj_res;
pub fn lean_byte_array_uset(a: lean_obj_arg, i: usize, v: u8) callconv(.C) LeanPtr {
    var r: lean_obj_res = undefined;
    if (lean_is_exclusive(a)) {
        r = a;
    } else {
        r = lean_copy_byte_array(a);
    }
    var it: [*c]u8 = lean_sarray_cptr(r) + i;
    it.* = v;
    return r;
}
pub fn lean_byte_array_set(a: lean_obj_arg, i: b_lean_obj_arg, b: u8) callconv(.C) lean_obj_res {
    if (!lean_is_scalar(i)) {
        return a;
    } else {
        var idx: usize = lean_unbox(i);
        if (idx >= lean_sarray_size(a)) {
            return a;
        } else {
            return lean_byte_array_uset(a, idx, b);
        }
    }
}
pub fn lean_byte_array_fset(a: lean_obj_arg, i: b_lean_obj_arg, b: u8) callconv(.C) lean_obj_res {
    return lean_byte_array_uset(a, lean_unbox(i), b);
}
pub extern fn lean_float_array_mk(a: lean_obj_arg) lean_obj_res;
pub extern fn lean_float_array_data(a: lean_obj_arg) lean_obj_res;
pub extern fn lean_copy_float_array(a: lean_obj_arg) lean_obj_res;
pub fn lean_mk_empty_float_array(capacity: b_lean_obj_arg) callconv(.C) lean_obj_res {
    if (!lean_is_scalar(capacity)) {
        lean_internal_panic_out_of_memory();
    }
    return lean_alloc_sarray(@as(c_uint, @bitCast(@as(c_uint, @truncate(@sizeOf(f64))))), 0, lean_unbox(capacity));
}
pub fn lean_float_array_size(a: b_lean_obj_arg) callconv(.C) lean_obj_res {
    return lean_box(lean_sarray_size(a));
}
pub fn lean_float_array_cptr(a: b_lean_obj_arg) callconv(.C) [*c]f64 {
    return @as([*c]f64, @ptrCast(@alignCast(lean_sarray_cptr(a))));
}
pub fn lean_float_array_uget(a: b_lean_obj_arg, i: usize) callconv(.C) f64 {
    return lean_float_array_cptr(a)[i];
}
pub fn lean_float_array_fget(a: b_lean_obj_arg, i: b_lean_obj_arg) callconv(.C) f64 {
    return lean_float_array_uget(a, lean_unbox(i));
}
pub fn lean_float_array_get(a: b_lean_obj_arg, i: b_lean_obj_arg) callconv(.C) f64 {
    if (lean_is_scalar(i)) {
        var idx: usize = lean_unbox(i);
        return if (idx < lean_sarray_size(a)) lean_float_array_uget(a, idx) else 0.0;
    } else {
        return 0.0;
    }
    return 0;
}
pub extern fn lean_float_array_push(a: lean_obj_arg, d: f64) lean_obj_res;
pub fn lean_float_array_uset(a: lean_obj_arg, i: usize, d: f64) callconv(.C) lean_obj_res {
    var r: lean_obj_res = undefined;
    if (lean_is_exclusive(a)) {
        r = a;
    } else {
        r = lean_copy_float_array(a);
    }
    var it: [*c]f64 = lean_float_array_cptr(r) + i;
    it.* = d;
    return r;
}
pub fn lean_float_array_fset(a: lean_obj_arg, i: b_lean_obj_arg, d: f64) callconv(.C) lean_obj_res {
    return lean_float_array_uset(a, lean_unbox(i), d);
}
pub fn lean_float_array_set(a: lean_obj_arg, i: b_lean_obj_arg, d: f64) callconv(.C) lean_obj_res {
    if (!lean_is_scalar(i)) {
        return a;
    } else {
        var idx: usize = lean_unbox(i);
        if (idx >= lean_sarray_size(a)) {
            return a;
        } else {
            return lean_float_array_uset(a, idx, d);
        }
    }
}
pub fn lean_alloc_string(size: usize, capacity: usize, len: usize) callconv(.C) lean_obj_res {
    var o: *lean_string_object = @as(*lean_string_object, @ptrCast(@alignCast(lean_alloc_object(@sizeOf(lean_string_object) +% capacity))));
    lean_set_st_header(@as(LeanPtr, @ptrCast(o)), @as(c_uint, @bitCast(@as(c_int, 249))), @as(c_uint, @bitCast(0)));
    o.*.m_size = size;
    o.*.m_capacity = capacity;
    o.*.m_length = len;
    return @as(LeanPtr, @ptrCast(o));
}
pub extern fn lean_utf8_strlen(str: [*:0]const u8) usize;
pub extern fn lean_utf8_n_strlen(str: [*:0]const u8, n: usize) usize;
pub fn lean_string_capacity(o: LeanPtr) callconv(.C) usize {
    return lean_to_string(o).*.m_capacity;
}
pub fn lean_string_byte_size(o: LeanPtr) callconv(.C) usize {
    return @sizeOf(lean_string_object) +% lean_string_capacity(o);
}
pub fn lean_char_default_value() callconv(.C) u32 {
    return 'A';
}
pub extern fn lean_mk_string_from_bytes(s: [*:0]const u8, sz: usize) lean_obj_res;
pub extern fn lean_mk_string(s: [*:0]const u8) lean_obj_res;
pub fn lean_string_cstr(o: b_lean_obj_arg) callconv(.C) [*:0]const u8 {
    assert(@src(), lean_is_string(o), "lean_is_string(o)");
    return lean_to_string(o).*.m_data();
}
pub fn lean_string_size(o: b_lean_obj_arg) callconv(.C) usize {
    return lean_to_string(o).*.m_size;
}
pub fn lean_string_len(o: b_lean_obj_arg) callconv(.C) usize {
    return lean_to_string(o).*.m_length;
}
pub extern fn lean_string_push(s: lean_obj_arg, c: u32) lean_obj_res;
pub extern fn lean_string_append(s1: lean_obj_arg, s2: b_lean_obj_arg) lean_obj_res;
pub fn lean_string_length(s: b_lean_obj_arg) callconv(.C) lean_obj_res {
    return lean_box(lean_string_len(s));
}
pub extern fn lean_string_mk(cs: lean_obj_arg) lean_obj_res;
pub extern fn lean_string_data(s: lean_obj_arg) lean_obj_res;
pub extern fn lean_string_utf8_get(s: b_lean_obj_arg, i: b_lean_obj_arg) u32;
pub extern fn lean_string_utf8_get_fast_cold(str: [*:0]const u8, i: usize, size: usize, c: u8) u32;
pub fn lean_string_utf8_get_fast(s: b_lean_obj_arg, i: b_lean_obj_arg) callconv(.C) u32 {
    var str: [*:0]const u8 = lean_string_cstr(s);
    var idx: usize = lean_unbox(i);
    var c: u8 = @as(u8, @bitCast(str[idx]));
    if ((@as(c_int, @bitCast(@as(c_uint, c))) & @as(c_int, 128)) == 0) return @as(u32, @bitCast(@as(c_uint, c)));
    return lean_string_utf8_get_fast_cold(str, idx, lean_string_size(s), c);
}
pub extern fn lean_string_utf8_next(s: b_lean_obj_arg, i: b_lean_obj_arg) lean_obj_res;
pub extern fn lean_string_utf8_next_fast_cold(i: usize, c: u8) lean_obj_res;
pub fn lean_string_utf8_next_fast(s: b_lean_obj_arg, i: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var str: [*:0]const u8 = lean_string_cstr(s);
    var idx: usize = lean_unbox(i);
    var c: u8 = @as(u8, @bitCast(str[idx]));
    if ((@as(c_int, @bitCast(@as(c_uint, c))) & @as(c_int, 128)) == 0) return lean_box(idx +% @as(usize, @bitCast(@as(c_long, @as(c_int, 1)))));
    return lean_string_utf8_next_fast_cold(idx, c);
}
pub extern fn lean_string_utf8_prev(s: b_lean_obj_arg, i: b_lean_obj_arg) lean_obj_res;
pub extern fn lean_string_utf8_set(s: lean_obj_arg, i: b_lean_obj_arg, c: u32) lean_obj_res;
pub fn lean_string_utf8_at_end(s: b_lean_obj_arg, i: b_lean_obj_arg) callconv(.C) u8 {
    return @as(u8, @intFromBool(!lean_is_scalar(i) or (lean_unbox(i) >= (lean_string_size(s) -% @as(usize, @bitCast(@as(c_long, @as(c_int, 1))))))));
}
pub extern fn lean_string_utf8_extract(s: b_lean_obj_arg, b: b_lean_obj_arg, e: b_lean_obj_arg) lean_obj_res;
pub fn lean_string_utf8_byte_size(s: b_lean_obj_arg) callconv(.C) lean_obj_res {
    return lean_box(lean_string_size(s) -% @as(usize, @bitCast(@as(c_long, @as(c_int, 1)))));
}
pub extern fn lean_string_eq_cold(s1: b_lean_obj_arg, s2: b_lean_obj_arg) bool;
pub fn lean_string_eq(s1: b_lean_obj_arg, s2: b_lean_obj_arg) callconv(.C) bool {
    return (s1 == s2) or ((lean_string_size(s1) == lean_string_size(s2)) and (@as(c_int, @intFromBool(lean_string_eq_cold(s1, s2))) != 0));
}
pub fn lean_string_ne(s1: b_lean_obj_arg, s2: b_lean_obj_arg) callconv(.C) bool {
    return !lean_string_eq(s1, s2);
}
pub extern fn lean_string_lt(s1: b_lean_obj_arg, s2: b_lean_obj_arg) bool;
pub fn lean_string_dec_eq(s1: b_lean_obj_arg, s2: b_lean_obj_arg) callconv(.C) u8 {
    return @as(u8, @intFromBool(lean_string_eq(s1, s2)));
}
pub fn lean_string_dec_lt(s1: b_lean_obj_arg, s2: b_lean_obj_arg) callconv(.C) u8 {
    return @as(u8, @intFromBool(lean_string_lt(s1, s2)));
}
pub extern fn lean_string_hash(b_lean_obj_arg) u64;
pub fn lean_mk_thunk(c: lean_obj_arg) callconv(.C) lean_obj_res {
    var o: *lean_thunk_object = @as(*lean_thunk_object, @ptrCast(@alignCast(lean_alloc_small_object(@as(c_uint, @bitCast(@as(c_uint, @truncate(@sizeOf(lean_thunk_object)))))))));
    lean_set_st_header(@as(LeanPtr, @ptrCast(o)), @as(c_uint, @bitCast(@as(c_int, 251))), @as(c_uint, @bitCast(0)));
    o.*.m_value = @as(LeanPtr, @ptrFromInt(0));
    o.*.m_closure = c;
    return @as(LeanPtr, @ptrCast(o));
}
pub fn lean_thunk_pure(v: lean_obj_arg) callconv(.C) lean_obj_res {
    var o: *lean_thunk_object = @as(*lean_thunk_object, @ptrCast(@alignCast(lean_alloc_small_object(@as(c_uint, @bitCast(@as(c_uint, @truncate(@sizeOf(lean_thunk_object)))))))));
    lean_set_st_header(@as(LeanPtr, @ptrCast(o)), @as(c_uint, @bitCast(@as(c_int, 251))), @as(c_uint, @bitCast(0)));
    o.*.m_value = v;
    o.*.m_closure = @as(LeanPtr, @ptrFromInt(0));
    return @as(LeanPtr, @ptrCast(o));
}
pub extern fn lean_thunk_get_core(t: LeanPtr) LeanPtr;
pub fn lean_thunk_get(t: b_lean_obj_arg) callconv(.C) b_lean_obj_res {
    var r: LeanPtr = lean_to_thunk(t).*.m_value;
    if (r != null) return r;
    return lean_thunk_get_core(t);
}
pub fn lean_thunk_get_own(t: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var r: LeanPtr = lean_thunk_get(t);
    lean_inc(r);
    return r;
}
pub extern fn lean_init_task_manager(...) void;
pub extern fn lean_init_task_manager_using(num_workers: c_uint) void;
pub extern fn lean_finalize_task_manager(...) void;
pub extern fn lean_task_spawn_core(c: lean_obj_arg, prio: c_uint, keep_alive: bool) lean_obj_res;
pub fn lean_task_spawn(c: lean_obj_arg, prio: lean_obj_arg) callconv(.C) lean_obj_res {
    return lean_task_spawn_core(c, @as(c_uint, @bitCast(@as(c_uint, @truncate(lean_unbox(prio))))), 0 != 0);
}
pub extern fn lean_task_pure(a: lean_obj_arg) lean_obj_res;
pub extern fn lean_task_bind_core(x: lean_obj_arg, f: lean_obj_arg, prio: c_uint, keep_alive: bool) lean_obj_res;
pub fn lean_task_bind(x: lean_obj_arg, f: lean_obj_arg, prio: lean_obj_arg) callconv(.C) lean_obj_res {
    return lean_task_bind_core(x, f, @as(c_uint, @bitCast(@as(c_uint, @truncate(lean_unbox(prio))))), 0 != 0);
}
pub extern fn lean_task_map_core(f: lean_obj_arg, t: lean_obj_arg, prio: c_uint, keep_alive: bool) lean_obj_res;
pub fn lean_task_map(f: lean_obj_arg, t: lean_obj_arg, prio: lean_obj_arg) callconv(.C) lean_obj_res {
    return lean_task_map_core(f, t, @as(c_uint, @bitCast(@as(c_uint, @truncate(lean_unbox(prio))))), 0 != 0);
}
pub extern fn lean_task_get(t: b_lean_obj_arg) b_lean_obj_res;
pub fn lean_task_get_own(t: lean_obj_arg) callconv(.C) lean_obj_res {
    var r: LeanPtr = lean_task_get(t);
    lean_inc(r);
    lean_dec(t);
    return r;
}
pub extern fn lean_io_check_canceled_core(...) bool;
pub extern fn lean_io_cancel_core(t: b_lean_obj_arg) void;
pub extern fn lean_io_has_finished_core(t: b_lean_obj_arg) bool;
pub extern fn lean_io_wait_any_core(task_list: b_lean_obj_arg) b_lean_obj_res;
pub fn lean_alloc_external(cls: [*c]lean_external_class, data: ?*anyopaque) callconv(.C) LeanPtr {
    var o: *lean_external_object = @as(*lean_external_object, @ptrCast(@alignCast(lean_alloc_small_object(@as(c_uint, @bitCast(@as(c_uint, @truncate(@sizeOf(lean_external_object)))))))));
    lean_set_st_header(@as(LeanPtr, @ptrCast(o)), @as(c_uint, @bitCast(@as(c_int, 254))), @as(c_uint, @bitCast(0)));
    o.*.m_class = cls;
    o.*.m_data = data;
    return @as(LeanPtr, @ptrCast(o));
}
pub fn lean_get_external_class(o: LeanPtr) callconv(.C) [*c]lean_external_class {
    return lean_to_external(o).*.m_class;
}
pub fn lean_get_external_data(o: LeanPtr) callconv(.C) ?*anyopaque {
    return lean_to_external(o).*.m_data;
}
pub extern fn lean_nat_big_succ(a: LeanPtr) LeanPtr;
pub extern fn lean_nat_big_add(a1: LeanPtr, a2: LeanPtr) LeanPtr;
pub extern fn lean_nat_big_sub(a1: LeanPtr, a2: LeanPtr) LeanPtr;
pub extern fn lean_nat_big_mul(a1: LeanPtr, a2: LeanPtr) LeanPtr;
pub extern fn lean_nat_overflow_mul(a1: usize, a2: usize) LeanPtr;
pub extern fn lean_nat_big_div(a1: LeanPtr, a2: LeanPtr) LeanPtr;
pub extern fn lean_nat_big_mod(a1: LeanPtr, a2: LeanPtr) LeanPtr;
pub extern fn lean_nat_big_eq(a1: LeanPtr, a2: LeanPtr) bool;
pub extern fn lean_nat_big_le(a1: LeanPtr, a2: LeanPtr) bool;
pub extern fn lean_nat_big_lt(a1: LeanPtr, a2: LeanPtr) bool;
pub extern fn lean_nat_big_land(a1: LeanPtr, a2: LeanPtr) LeanPtr;
pub extern fn lean_nat_big_lor(a1: LeanPtr, a2: LeanPtr) LeanPtr;
pub extern fn lean_nat_big_xor(a1: LeanPtr, a2: LeanPtr) LeanPtr;
pub extern fn lean_cstr_to_nat(n: [*:0]const u8) lean_obj_res;
pub extern fn lean_big_usize_to_nat(n: usize) lean_obj_res;
pub extern fn lean_big_uint64_to_nat(n: u64) lean_obj_res;
pub fn lean_usize_to_nat(n: usize) callconv(.C) lean_obj_res {
    if (LEAN_LIKELY(n <= LEAN_MAX_SMALL_NAT))
        return lean_box(n)
    else
        return lean_big_usize_to_nat(n);
}
pub fn lean_unsigned_to_nat(n: c_uint) callconv(.C) lean_obj_res {
    return lean_usize_to_nat(@intCast(n));
}
pub fn lean_uint64_to_nat(n: u64) callconv(.C) lean_obj_res {
    if (LEAN_LIKELY(n <= LEAN_MAX_SMALL_NAT))
        return lean_box(n)
    else
        return lean_big_uint64_to_nat(n);
}
pub fn lean_nat_succ(a: b_lean_obj_arg) callconv(.C) lean_obj_res {
    if (LEAN_LIKELY(lean_is_scalar(a)))
        return lean_usize_to_nat(lean_unbox(a) + 1)
    else
        return lean_nat_big_succ(a);
}
pub fn lean_nat_add(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    if (LEAN_LIKELY(lean_is_scalar(a1) and lean_is_scalar(a2)))
        return lean_usize_to_nat(lean_unbox(a1) + lean_unbox(a2))
    else
        return lean_nat_big_add(a1, a2);
}
pub fn lean_nat_sub(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    if (LEAN_LIKELY(lean_is_scalar(a1) and lean_is_scalar(a2))) {
        var n1: usize = lean_unbox(a1);
        var n2: usize = lean_unbox(a2);
        if (n1 < n2)
            return lean_box(0)
        else
            return lean_box(n1 - n2);
    } else {
        return lean_nat_big_sub(a1, a2);
    }
}
pub fn lean_nat_mul(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    if (LEAN_LIKELY(lean_is_scalar(a1) and lean_is_scalar(a2))) {
        var n1: usize = lean_unbox(a1);
        if (n1 == 0) return a1;
        var n2: usize = lean_unbox(a2);
        var r: usize = n1 *% n2;
        if (r <= LEAN_MAX_SMALL_NAT and r / n1 == n2)
            return lean_box(r)
        else
            return lean_nat_overflow_mul(n1, n2);
    } else {
        return lean_nat_big_mul(a1, a2);
    }
}
pub fn lean_nat_div(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    if (LEAN_LIKELY(lean_is_scalar(a1) and lean_is_scalar(a2))) {
        var n1: usize = lean_unbox(a1);
        var n2: usize = lean_unbox(a2);
        if (n2 == 0) return lean_box(0) else return lean_box(n1 / n2);
    } else {
        return lean_nat_big_div(a1, a2);
    }
}
pub fn lean_nat_mod(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    if (LEAN_LIKELY(lean_is_scalar(a1) and lean_is_scalar(a2))) {
        var n1: usize = lean_unbox(a1);
        var n2: usize = lean_unbox(a2);
        if (n2 == 0) return lean_box(n1) else return lean_box(n1 % n2);
    } else {
        return lean_nat_big_mod(a1, a2);
    }
}
pub fn lean_nat_eq(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) bool {
    if (LEAN_LIKELY(lean_is_scalar(a1) and lean_is_scalar(a2))) {
        return a1 == a2;
    } else {
        return lean_nat_big_eq(a1, a2);
    }
    return false;
}
pub fn lean_nat_dec_eq(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) u8 {
    return lean_nat_eq(a1, a2);
}
pub fn lean_nat_ne(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) bool {
    return !lean_nat_eq(a1, a2);
}
pub fn lean_nat_le(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) bool {
    if (LEAN_LIKELY(lean_is_scalar(a1) and lean_is_scalar(a2))) {
        return a1 <= a2;
    } else {
        return lean_nat_big_le(a1, a2);
    }
    return false;
}
pub fn lean_nat_dec_le(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) u8 {
    return @as(u8, @intFromBool(lean_nat_le(a1, a2)));
}
pub fn lean_nat_lt(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) bool {
    if (LEAN_LIKELY(lean_is_scalar(a1) and lean_is_scalar(a2))) {
        return a1 < a2;
    } else {
        return lean_nat_big_lt(a1, a2);
    }
    return false;
}
pub fn lean_nat_dec_lt(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) u8 {
    return @intFromBool(lean_nat_lt(a1, a2));
}
pub fn lean_nat_land(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    if (LEAN_LIKELY(lean_is_scalar(a1) and lean_is_scalar(a2))) {
        return @ptrFromInt(@intFromPtr(a1) & @intFromPtr(a2));
    } else {
        return lean_nat_big_land(a1, a2);
    }
}
pub fn lean_nat_lor(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    if (LEAN_LIKELY(lean_is_scalar(a1) and lean_is_scalar(a2))) {
        return @ptrFromInt(@intFromPtr(a1) | @intFromPtr(a2));
    } else {
        return lean_nat_big_lor(a1, a2);
    }
}
pub fn lean_nat_lxor(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    if (LEAN_LIKELY(lean_is_scalar(a1) and lean_is_scalar(a2))) {
        return lean_box(lean_unbox(a1) ^ lean_unbox(a2));
    } else {
        return lean_nat_big_xor(a1, a2);
    }
}
pub extern fn lean_nat_shiftl(a1: b_lean_obj_arg, a2: b_lean_obj_arg) lean_obj_res;
pub extern fn lean_nat_shiftr(a1: b_lean_obj_arg, a2: b_lean_obj_arg) lean_obj_res;
pub extern fn lean_nat_pow(a1: b_lean_obj_arg, a2: b_lean_obj_arg) lean_obj_res;
pub extern fn lean_nat_gcd(a1: b_lean_obj_arg, a2: b_lean_obj_arg) lean_obj_res;
pub extern fn lean_nat_log2(a: b_lean_obj_arg) lean_obj_res;
pub extern fn lean_int_big_neg(a: LeanPtr) LeanPtr;
pub extern fn lean_int_big_add(a1: LeanPtr, a2: LeanPtr) LeanPtr;
pub extern fn lean_int_big_sub(a1: LeanPtr, a2: LeanPtr) LeanPtr;
pub extern fn lean_int_big_mul(a1: LeanPtr, a2: LeanPtr) LeanPtr;
pub extern fn lean_int_big_div(a1: LeanPtr, a2: LeanPtr) LeanPtr;
pub extern fn lean_int_big_mod(a1: LeanPtr, a2: LeanPtr) LeanPtr;
pub extern fn lean_int_big_eq(a1: LeanPtr, a2: LeanPtr) bool;
pub extern fn lean_int_big_le(a1: LeanPtr, a2: LeanPtr) bool;
pub extern fn lean_int_big_lt(a1: LeanPtr, a2: LeanPtr) bool;
pub extern fn lean_int_big_nonneg(a: LeanPtr) bool;
pub extern fn lean_cstr_to_int(n: [*:0]const u8) LeanPtr;
pub extern fn lean_big_int_to_int(n: c_int) LeanPtr;
pub extern fn lean_big_size_t_to_int(n: usize) LeanPtr;
pub extern fn lean_big_int64_to_int(n: i64) LeanPtr;
pub fn lean_int_to_int(n: c_int) callconv(.C) lean_obj_res {
    if (@sizeOf(*anyopaque) == 8)
        return lean_box(@as(c_uint, @bitCast(n)))
    else if (LEAN_LIKELY(LEAN_MIN_SMALL_INT <= n and n <= LEAN_MAX_SMALL_INT))
        return lean_box(@as(c_uint, @bitCast(n)))
    else
        return lean_big_int_to_int(n);
}
pub fn lean_int64_to_int(n: i64) callconv(.C) lean_obj_res {
    if (LEAN_LIKELY(LEAN_MIN_SMALL_INT <= n and n <= LEAN_MAX_SMALL_INT))
        return lean_box(@bitCast(@as(isize, @truncate(n))))
    else
        return lean_big_int64_to_int(n);
}
pub fn lean_scalar_to_int64(a: b_lean_obj_arg) callconv(.C) i64 {
    assert(@src(), lean_is_scalar(a), "lean_is_scalar(a)");
    if (@sizeOf(*anyopaque) == 8)
        return @intCast(@as(isize, @bitCast(lean_unbox(a))))
    else
        return @intCast(@as(isize, @bitCast(@intFromPtr(a))) >> 1);
}
pub fn lean_scalar_to_int(a: b_lean_obj_arg) callconv(.C) c_int {
    assert(@src(), lean_is_scalar(a), "lean_is_scalar(a)");
    if (@sizeOf(*anyopaque) == 8) return @as(c_int, @bitCast(@as(c_uint, @bitCast(@as(c_uint, @truncate(lean_unbox(a))))))) else return @as(c_int, @bitCast(@as(c_uint, @truncate(@as(usize, @intCast(@intFromPtr(a))))))) >> @intCast(1);
    return 0;
}
pub fn lean_nat_to_int(a: lean_obj_arg) callconv(.C) lean_obj_res {
    if (lean_is_scalar(a)) {
        var v: usize = lean_unbox(a);
        if (v <= LEAN_MAX_SMALL_INT) return a else return lean_big_size_t_to_int(v);
    } else {
        return a;
    }
}
pub fn lean_int_neg(a: b_lean_obj_arg) callconv(.C) lean_obj_res {
    if (LEAN_LIKELY(lean_is_scalar(a))) {
        return lean_int64_to_int(-lean_scalar_to_int64(a));
    } else {
        return lean_int_big_neg(a);
    }
}
pub fn lean_int_neg_succ_of_nat(a: lean_obj_arg) callconv(.C) lean_obj_res {
    var s = lean_nat_succ(a);
    lean_dec(a);
    var i = lean_nat_to_int(s);
    var r = lean_int_neg(i);
    lean_dec(i);
    return r;
}
pub fn lean_int_add(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    if (LEAN_LIKELY(lean_is_scalar(a1) and lean_is_scalar(a2))) {
        return lean_int64_to_int(lean_scalar_to_int64(a1) + lean_scalar_to_int64(a2));
    } else {
        return lean_int_big_add(a1, a2);
    }
}
pub fn lean_int_sub(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    if (LEAN_LIKELY(lean_is_scalar(a1) and lean_is_scalar(a2))) {
        return lean_int64_to_int(lean_scalar_to_int64(a1) - lean_scalar_to_int64(a2));
    } else {
        return lean_int_big_sub(a1, a2);
    }
}
pub fn lean_int_mul(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    if (LEAN_LIKELY(lean_is_scalar(a1) and lean_is_scalar(a2))) {
        return lean_int64_to_int(lean_scalar_to_int64(a1) * lean_scalar_to_int64(a2));
    } else {
        return lean_int_big_mul(a1, a2);
    }
}
pub fn lean_int_div(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    if (LEAN_LIKELY(lean_is_scalar(a1) and lean_is_scalar(a2))) {
        if (@sizeOf(*anyopaque) == 8) {
            var v1: i64 = lean_scalar_to_int(a1);
            var v2: i64 = lean_scalar_to_int(a2);
            if (v2 == 0) return lean_box(0) else return lean_int64_to_int(@divTrunc(v1, v2));
        } else {
            var v1: c_int = lean_scalar_to_int(a1);
            var v2: c_int = lean_scalar_to_int(a2);
            if (v2 == 0) return lean_box(0) else return lean_int_to_int(@divTrunc(v1, v2));
        }
    } else {
        return lean_int_big_div(a1, a2);
    }
}
pub fn lean_int_mod(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    if (LEAN_LIKELY(lean_is_scalar(a1) and lean_is_scalar(a2))) {
        if (@sizeOf(*anyopaque) == 8) {
            var v1: i64 = lean_scalar_to_int64(a1);
            var v2: i64 = lean_scalar_to_int64(a2);
            if (v2 == 0) return a1 else return lean_int64_to_int(std.zig.c_translation.signedRemainder(v1, v2));
        } else {
            var v1: c_int = lean_scalar_to_int(a1);
            var v2: c_int = lean_scalar_to_int(a2);
            if (v2 == 0) return a1 else return lean_int_to_int(std.zig.c_translation.signedRemainder(v1, v2));
        }
    } else {
        return lean_int_big_mod(a1, a2);
    }
}
pub fn lean_int_eq(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) bool {
    if (LEAN_LIKELY(lean_is_scalar(a1) and lean_is_scalar(a2))) {
        return a1 == a2;
    } else {
        return lean_int_big_eq(a1, a2);
    }
    return false;
}
pub fn lean_int_ne(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) bool {
    return !lean_int_eq(a1, a2);
}
pub fn lean_int_le(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) bool {
    if (LEAN_LIKELY(lean_is_scalar(a1) and lean_is_scalar(a2))) {
        return lean_scalar_to_int(a1) <= lean_scalar_to_int(a2);
    } else {
        return lean_int_big_le(a1, a2);
    }
    return false;
}
pub fn lean_int_lt(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) bool {
    if (LEAN_LIKELY(lean_is_scalar(a1) and lean_is_scalar(a2))) {
        return lean_scalar_to_int(a1) < lean_scalar_to_int(a2);
    } else {
        return lean_int_big_lt(a1, a2);
    }
    return false;
}
pub extern fn lean_big_int_to_nat(a: lean_obj_arg) lean_obj_res;
pub fn lean_int_to_nat(a: lean_obj_arg) callconv(.C) lean_obj_res {
    assert(@src(), !lean_int_lt(a, lean_box(0)), "!lean_int_lt(a, lean_box(0))");
    if (lean_is_scalar(a)) {
        return a;
    } else {
        return lean_big_int_to_nat(a);
    }
}
pub fn lean_nat_abs(i: b_lean_obj_arg) callconv(.C) lean_obj_res {
    if (lean_int_lt(i, lean_box(0))) {
        return lean_int_to_nat(lean_int_neg(i));
    } else {
        lean_inc(i);
        return lean_int_to_nat(i);
    }
}
pub fn lean_int_dec_eq(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) u8 {
    return lean_int_eq(a1, a2);
}
pub fn lean_int_dec_le(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) u8 {
    return lean_int_le(a1, a2);
}
pub fn lean_int_dec_lt(a1: b_lean_obj_arg, a2: b_lean_obj_arg) callconv(.C) u8 {
    return lean_int_lt(a1, a2);
}
pub fn lean_int_dec_nonneg(a: b_lean_obj_arg) callconv(.C) u8 {
    if (LEAN_LIKELY(lean_is_scalar(a)))
        return lean_scalar_to_int(a) >= 0
    else
        return lean_int_big_nonneg(a);
}
pub fn lean_bool_to_uint64(a: u8) callconv(.C) u64 {
    return a;
}
pub extern fn lean_uint8_of_big_nat(a: b_lean_obj_arg) u8;
pub fn lean_uint8_of_nat(a: b_lean_obj_arg) callconv(.C) u8 {
    if (@as(c_int, @intFromBool(lean_is_scalar(a))) != 0)
        return @as(u8, @truncate(lean_unbox(a)))
    else
        return lean_uint8_of_big_nat(a);
}
pub fn lean_uint8_of_nat_mk(a: lean_obj_arg) callconv(.C) u8 {
    var r = lean_uint8_of_nat(a);
    lean_dec(a);
    return r;
}
pub fn lean_uint8_to_nat(a: u8) callconv(.C) lean_obj_res {
    return lean_usize_to_nat(a);
}
pub fn lean_uint8_add(a1: u8, a2: u8) callconv(.C) u8 {
    return @as(u8, @bitCast(@as(i8, @truncate(@as(c_int, @bitCast(@as(c_uint, a1))) + @as(c_int, @bitCast(@as(c_uint, a2)))))));
}
pub fn lean_uint8_sub(a1: u8, a2: u8) callconv(.C) u8 {
    return @as(u8, @bitCast(@as(i8, @truncate(@as(c_int, @bitCast(@as(c_uint, a1))) - @as(c_int, @bitCast(@as(c_uint, a2)))))));
}
pub fn lean_uint8_mul(a1: u8, a2: u8) callconv(.C) u8 {
    return @as(u8, @bitCast(@as(i8, @truncate(@as(c_int, @bitCast(@as(c_uint, a1))) * @as(c_int, @bitCast(@as(c_uint, a2)))))));
}
pub fn lean_uint8_div(a1: u8, a2: u8) callconv(.C) u8 {
    return @as(u8, @bitCast(@as(i8, @truncate(if (@as(c_int, @bitCast(@as(c_uint, a2))) == 0) 0 else @divTrunc(@as(c_int, @bitCast(@as(c_uint, a1))), @as(c_int, @bitCast(@as(c_uint, a2))))))));
}
pub fn lean_uint8_mod(a1: u8, a2: u8) callconv(.C) u8 {
    return @as(u8, @bitCast(@as(i8, @truncate(if (@as(c_int, @bitCast(@as(c_uint, a2))) == 0) @as(c_int, @bitCast(@as(c_uint, a1))) else std.zig.c_translation.signedRemainder(@as(c_int, @bitCast(@as(c_uint, a1))), @as(c_int, @bitCast(@as(c_uint, a2))))))));
}
pub fn lean_uint8_land(a: u8, b: u8) callconv(.C) u8 {
    return @as(u8, @bitCast(@as(i8, @truncate(@as(c_int, @bitCast(@as(c_uint, a))) & @as(c_int, @bitCast(@as(c_uint, b)))))));
}
pub fn lean_uint8_lor(a: u8, b: u8) callconv(.C) u8 {
    return @as(u8, @bitCast(@as(i8, @truncate(@as(c_int, @bitCast(@as(c_uint, a))) | @as(c_int, @bitCast(@as(c_uint, b)))))));
}
pub fn lean_uint8_xor(a: u8, b: u8) callconv(.C) u8 {
    return @as(u8, @bitCast(@as(i8, @truncate(@as(c_int, @bitCast(@as(c_uint, a))) ^ @as(c_int, @bitCast(@as(c_uint, b)))))));
}
pub fn lean_uint8_shift_left(a: u8, b: u8) callconv(.C) u8 {
    return @as(u8, @bitCast(@as(i8, @truncate(@as(c_int, @bitCast(@as(c_uint, a))) << @intCast(std.zig.c_translation.signedRemainder(@as(c_int, @bitCast(@as(c_uint, b))), @as(c_int, 8)))))));
}
pub fn lean_uint8_shift_right(a: u8, b: u8) callconv(.C) u8 {
    return @as(u8, @bitCast(@as(i8, @truncate(@as(c_int, @bitCast(@as(c_uint, a))) >> @intCast(std.zig.c_translation.signedRemainder(@as(c_int, @bitCast(@as(c_uint, b))), @as(c_int, 8)))))));
}
pub fn lean_uint8_complement(a: u8) callconv(.C) u8 {
    return @as(u8, @bitCast(@as(i8, @truncate(~@as(c_int, @bitCast(@as(c_uint, a)))))));
}
pub fn lean_uint8_modn(a1: u8, a2: b_lean_obj_arg) callconv(.C) u8 {
    if (__builtin_expect(@as(c_long, @intFromBool(lean_is_scalar(a2))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        var n2: c_uint = @as(c_uint, @bitCast(@as(c_uint, @truncate(lean_unbox(a2)))));
        return @as(u8, @bitCast(@as(u8, @truncate(if (n2 == @as(c_uint, @bitCast(0))) @as(c_uint, @bitCast(@as(c_uint, a1))) else @as(c_uint, @bitCast(@as(c_uint, a1))) % n2))));
    } else {
        return a1;
    }
    return std.mem.zeroes(u8);
}
pub fn lean_uint8_log2(a: u8) callconv(.C) u8 {
    var res: u8 = 0;
    while (@as(c_int, @bitCast(@as(c_uint, a))) >= @as(c_int, 2)) {
        res +%= 1;
        a /= @as(u8, @bitCast(@as(i8, @truncate(@as(c_int, 2)))));
    }
    return res;
}
pub fn lean_uint8_dec_eq(a1: u8, a2: u8) callconv(.C) u8 {
    return @as(u8, @intFromBool(@as(c_int, @bitCast(@as(c_uint, a1))) == @as(c_int, @bitCast(@as(c_uint, a2)))));
}
pub fn lean_uint8_dec_lt(a1: u8, a2: u8) callconv(.C) u8 {
    return @as(u8, @intFromBool(@as(c_int, @bitCast(@as(c_uint, a1))) < @as(c_int, @bitCast(@as(c_uint, a2)))));
}
pub fn lean_uint8_dec_le(a1: u8, a2: u8) callconv(.C) u8 {
    return @as(u8, @intFromBool(@as(c_int, @bitCast(@as(c_uint, a1))) <= @as(c_int, @bitCast(@as(c_uint, a2)))));
}
pub fn lean_uint8_to_uint16(a: u8) callconv(.C) u16 {
    return @as(u16, @bitCast(@as(c_ushort, a)));
}
pub fn lean_uint8_to_uint32(a: u8) callconv(.C) u32 {
    return @as(u32, @bitCast(@as(c_uint, a)));
}
pub fn lean_uint8_to_uint64(a: u8) callconv(.C) u64 {
    return @as(u64, @bitCast(@as(c_ulong, a)));
}
pub extern fn lean_uint16_of_big_nat(a: b_lean_obj_arg) u16;
pub fn lean_uint16_of_nat(a: b_lean_obj_arg) callconv(.C) u16 {
    return @as(u16, @bitCast(@as(c_short, @truncate(if (@as(c_int, @intFromBool(lean_is_scalar(a))) != 0) @as(c_int, @bitCast(@as(c_int, @as(i16, @bitCast(@as(c_ushort, @truncate(lean_unbox(a)))))))) else @as(c_int, @bitCast(@as(c_uint, lean_uint16_of_big_nat(a))))))));
}
pub fn lean_uint16_of_nat_mk(a: lean_obj_arg) callconv(.C) u16 {
    var r: u16 = lean_uint16_of_nat(a);
    lean_dec(a);
    return r;
}
pub fn lean_uint16_to_nat(a: u16) callconv(.C) lean_obj_res {
    return lean_usize_to_nat(@as(usize, @bitCast(@as(c_ulong, a))));
}
pub fn lean_uint16_add(a1: u16, a2: u16) callconv(.C) u16 {
    return @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, @bitCast(@as(c_uint, a1))) + @as(c_int, @bitCast(@as(c_uint, a2)))))));
}
pub fn lean_uint16_sub(a1: u16, a2: u16) callconv(.C) u16 {
    return @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, @bitCast(@as(c_uint, a1))) - @as(c_int, @bitCast(@as(c_uint, a2)))))));
}
pub fn lean_uint16_mul(a1: u16, a2: u16) callconv(.C) u16 {
    return @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, @bitCast(@as(c_uint, a1))) * @as(c_int, @bitCast(@as(c_uint, a2)))))));
}
pub fn lean_uint16_div(a1: u16, a2: u16) callconv(.C) u16 {
    return @as(u16, @bitCast(@as(c_short, @truncate(if (@as(c_int, @bitCast(@as(c_uint, a2))) == 0) 0 else @divTrunc(@as(c_int, @bitCast(@as(c_uint, a1))), @as(c_int, @bitCast(@as(c_uint, a2))))))));
}
pub fn lean_uint16_mod(a1: u16, a2: u16) callconv(.C) u16 {
    return @as(u16, @bitCast(@as(c_short, @truncate(if (@as(c_int, @bitCast(@as(c_uint, a2))) == 0) @as(c_int, @bitCast(@as(c_uint, a1))) else std.zig.c_translation.signedRemainder(@as(c_int, @bitCast(@as(c_uint, a1))), @as(c_int, @bitCast(@as(c_uint, a2))))))));
}
pub fn lean_uint16_land(a: u16, b: u16) callconv(.C) u16 {
    return @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, @bitCast(@as(c_uint, a))) & @as(c_int, @bitCast(@as(c_uint, b)))))));
}
pub fn lean_uint16_lor(a: u16, b: u16) callconv(.C) u16 {
    return @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, @bitCast(@as(c_uint, a))) | @as(c_int, @bitCast(@as(c_uint, b)))))));
}
pub fn lean_uint16_xor(a: u16, b: u16) callconv(.C) u16 {
    return @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, @bitCast(@as(c_uint, a))) ^ @as(c_int, @bitCast(@as(c_uint, b)))))));
}
pub fn lean_uint16_shift_left(a: u16, b: u16) callconv(.C) u16 {
    return @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, @bitCast(@as(c_uint, a))) << @intCast(std.zig.c_translation.signedRemainder(@as(c_int, @bitCast(@as(c_uint, b))), @as(c_int, 16)))))));
}
pub fn lean_uint16_shift_right(a: u16, b: u16) callconv(.C) u16 {
    return @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, @bitCast(@as(c_uint, a))) >> @intCast(std.zig.c_translation.signedRemainder(@as(c_int, @bitCast(@as(c_uint, b))), @as(c_int, 16)))))));
}
pub fn lean_uint16_complement(a: u16) callconv(.C) u16 {
    return @as(u16, @bitCast(@as(c_short, @truncate(~@as(c_int, @bitCast(@as(c_uint, a)))))));
}
pub fn lean_uint16_modn(a1: u16, a2: b_lean_obj_arg) callconv(.C) u16 {
    if (__builtin_expect(@as(c_long, @intFromBool(lean_is_scalar(a2))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        var n2: c_uint = @as(c_uint, @bitCast(@as(c_uint, @truncate(lean_unbox(a2)))));
        return @as(u16, @bitCast(@as(c_ushort, @truncate(if (n2 == @as(c_uint, @bitCast(0))) @as(c_uint, @bitCast(@as(c_uint, a1))) else @as(c_uint, @bitCast(@as(c_uint, a1))) % n2))));
    } else {
        return a1;
    }
    return std.mem.zeroes(u16);
}
pub fn lean_uint16_log2(a: u16) callconv(.C) u16 {
    var res: u16 = 0;
    while (@as(c_int, @bitCast(@as(c_uint, a))) >= @as(c_int, 2)) {
        res +%= 1;
        a /= @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, 2)))));
    }
    return res;
}
pub fn lean_uint16_dec_eq(a1: u16, a2: u16) callconv(.C) u8 {
    return @as(u8, @intFromBool(@as(c_int, @bitCast(@as(c_uint, a1))) == @as(c_int, @bitCast(@as(c_uint, a2)))));
}
pub fn lean_uint16_dec_lt(a1: u16, a2: u16) callconv(.C) u8 {
    return @as(u8, @intFromBool(@as(c_int, @bitCast(@as(c_uint, a1))) < @as(c_int, @bitCast(@as(c_uint, a2)))));
}
pub fn lean_uint16_dec_le(a1: u16, a2: u16) callconv(.C) u8 {
    return @as(u8, @intFromBool(@as(c_int, @bitCast(@as(c_uint, a1))) <= @as(c_int, @bitCast(@as(c_uint, a2)))));
}
pub fn lean_uint16_to_uint8(a: u16) callconv(.C) u8 {
    return @as(u8, @bitCast(@as(u8, @truncate(a))));
}
pub fn lean_uint16_to_uint32(a: u16) callconv(.C) u32 {
    return @as(u32, @bitCast(@as(c_uint, a)));
}
pub fn lean_uint16_to_uint64(a: u16) callconv(.C) u64 {
    return @as(u64, @bitCast(@as(c_ulong, a)));
}
pub extern fn lean_uint32_of_big_nat(a: b_lean_obj_arg) u32;
pub fn lean_uint32_of_nat(a: b_lean_obj_arg) callconv(.C) u32 {
    return if (@as(c_int, @intFromBool(lean_is_scalar(a))) != 0) @as(u32, @bitCast(@as(c_uint, @truncate(lean_unbox(a))))) else lean_uint32_of_big_nat(a);
}
pub fn lean_uint32_of_nat_mk(a: lean_obj_arg) callconv(.C) u32 {
    var r: u32 = lean_uint32_of_nat(a);
    lean_dec(a);
    return r;
}
pub fn lean_uint32_to_nat(a: u32) callconv(.C) lean_obj_res {
    return lean_usize_to_nat(@as(usize, @bitCast(@as(c_ulong, a))));
}
pub fn lean_uint32_add(a1: u32, a2: u32) callconv(.C) u32 {
    return a1 +% a2;
}
pub fn lean_uint32_sub(a1: u32, a2: u32) callconv(.C) u32 {
    return a1 -% a2;
}
pub fn lean_uint32_mul(a1: u32, a2: u32) callconv(.C) u32 {
    return a1 *% a2;
}
pub fn lean_uint32_div(a1: u32, a2: u32) callconv(.C) u32 {
    return if (a2 == @as(u32, @bitCast(0))) @as(u32, @bitCast(0)) else a1 / a2;
}
pub fn lean_uint32_mod(a1: u32, a2: u32) callconv(.C) u32 {
    return if (a2 == @as(u32, @bitCast(0))) a1 else a1 % a2;
}
pub fn lean_uint32_land(a: u32, b: u32) callconv(.C) u32 {
    return a & b;
}
pub fn lean_uint32_lor(a: u32, b: u32) callconv(.C) u32 {
    return a | b;
}
pub fn lean_uint32_xor(a: u32, b: u32) callconv(.C) u32 {
    return a ^ b;
}
pub fn lean_uint32_shift_left(a: u32, b: u32) callconv(.C) u32 {
    return a << @intCast(b % @as(u32, @bitCast(@as(c_int, 32))));
}
pub fn lean_uint32_shift_right(a: u32, b: u32) callconv(.C) u32 {
    return a >> @intCast(b % @as(u32, @bitCast(@as(c_int, 32))));
}
pub fn lean_uint32_complement(a: u32) callconv(.C) u32 {
    return ~a;
}
pub extern fn lean_uint32_big_modn(a1: u32, a2: b_lean_obj_arg) u32;
pub fn lean_uint32_modn(a1: u32, a2: b_lean_obj_arg) callconv(.C) u32 {
    if (__builtin_expect(@as(c_long, @intFromBool(lean_is_scalar(a2))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        var n2: usize = lean_unbox(a2);
        return @as(u32, @bitCast(@as(c_uint, @truncate(if (n2 == 0) @as(usize, @bitCast(@as(c_ulong, a1))) else @as(usize, @bitCast(@as(c_ulong, a1))) % n2))));
    } else if (@sizeOf(*anyopaque) == @as(c_ulong, @bitCast(@as(c_long, @as(c_int, 4))))) {
        return lean_uint32_big_modn(a1, a2);
    } else {
        return a1;
    }
    return std.mem.zeroes(u32);
}
pub fn lean_uint32_log2(a: u32) callconv(.C) u32 {
    var res: u32 = 0;
    while (a >= @as(u32, @bitCast(@as(c_int, 2)))) {
        res +%= 1;
        a /= @as(u32, @bitCast(@as(c_int, 2)));
    }
    return res;
}
pub fn lean_uint32_dec_eq(a1: u32, a2: u32) callconv(.C) u8 {
    return @as(u8, @intFromBool(a1 == a2));
}
pub fn lean_uint32_dec_lt(a1: u32, a2: u32) callconv(.C) u8 {
    return @as(u8, @intFromBool(a1 < a2));
}
pub fn lean_uint32_dec_le(a1: u32, a2: u32) callconv(.C) u8 {
    return @as(u8, @intFromBool(a1 <= a2));
}
pub fn lean_uint32_to_uint8(a: u32) callconv(.C) u8 {
    return @as(u8, @bitCast(@as(u8, @truncate(a))));
}
pub fn lean_uint32_to_uint16(a: u32) callconv(.C) u16 {
    return @as(u16, @bitCast(@as(c_ushort, @truncate(a))));
}
pub fn lean_uint32_to_uint64(a: u32) callconv(.C) u64 {
    return @as(u64, @bitCast(@as(c_ulong, a)));
}
pub fn lean_uint32_to_usize(a: u32) callconv(.C) usize {
    return @as(usize, @bitCast(@as(c_ulong, a)));
}
pub extern fn lean_uint64_of_big_nat(a: b_lean_obj_arg) u64;
pub fn lean_uint64_of_nat(a: b_lean_obj_arg) callconv(.C) u64 {
    return if (@as(c_int, @intFromBool(lean_is_scalar(a))) != 0) @as(u64, @bitCast(lean_unbox(a))) else lean_uint64_of_big_nat(a);
}
pub fn lean_uint64_of_nat_mk(a: lean_obj_arg) callconv(.C) u64 {
    var r: u64 = lean_uint64_of_nat(a);
    lean_dec(a);
    return r;
}
pub fn lean_uint64_add(a1: u64, a2: u64) callconv(.C) u64 {
    return a1 +% a2;
}
pub fn lean_uint64_sub(a1: u64, a2: u64) callconv(.C) u64 {
    return a1 -% a2;
}
pub fn lean_uint64_mul(a1: u64, a2: u64) callconv(.C) u64 {
    return a1 *% a2;
}
pub fn lean_uint64_div(a1: u64, a2: u64) callconv(.C) u64 {
    return if (a2 == @as(u64, @bitCast(@as(c_long, 0)))) @as(u64, @bitCast(@as(c_long, 0))) else a1 / a2;
}
pub fn lean_uint64_mod(a1: u64, a2: u64) callconv(.C) u64 {
    return if (a2 == @as(u64, @bitCast(@as(c_long, 0)))) a1 else a1 % a2;
}
pub fn lean_uint64_land(a: u64, b: u64) callconv(.C) u64 {
    return a & b;
}
pub fn lean_uint64_lor(a: u64, b: u64) callconv(.C) u64 {
    return a | b;
}
pub fn lean_uint64_xor(a: u64, b: u64) callconv(.C) u64 {
    return a ^ b;
}
pub fn lean_uint64_shift_left(a: u64, b: u64) callconv(.C) u64 {
    return a << @intCast(b % @as(u64, @bitCast(@as(c_long, @as(c_int, 64)))));
}
pub fn lean_uint64_shift_right(a: u64, b: u64) callconv(.C) u64 {
    return a >> @intCast(b % @as(u64, @bitCast(@as(c_long, @as(c_int, 64)))));
}
pub fn lean_uint64_complement(a: u64) callconv(.C) u64 {
    return ~a;
}
pub extern fn lean_uint64_big_modn(a1: u64, a2: b_lean_obj_arg) u64;
pub fn lean_uint64_modn(a1: u64, a2: b_lean_obj_arg) callconv(.C) u64 {
    if (__builtin_expect(@as(c_long, @intFromBool(lean_is_scalar(a2))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        var n2: usize = lean_unbox(a2);
        return if (n2 == 0) a1 else a1 % n2;
    } else {
        return lean_uint64_big_modn(a1, a2);
    }
    return std.mem.zeroes(u64);
}
pub fn lean_uint64_log2(a: u64) callconv(.C) u64 {
    var res: u64 = 0;
    while (a >= @as(u64, @bitCast(@as(c_long, @as(c_int, 2))))) {
        res +%= 1;
        a /= @as(u64, @bitCast(@as(c_long, @as(c_int, 2))));
    }
    return res;
}
pub fn lean_uint64_dec_eq(a1: u64, a2: u64) callconv(.C) u8 {
    return @as(u8, @intFromBool(a1 == a2));
}
pub fn lean_uint64_dec_lt(a1: u64, a2: u64) callconv(.C) u8 {
    return @as(u8, @intFromBool(a1 < a2));
}
pub fn lean_uint64_dec_le(a1: u64, a2: u64) callconv(.C) u8 {
    return @as(u8, @intFromBool(a1 <= a2));
}
pub extern fn lean_uint64_mix_hash(a1: u64, a2: u64) u64;
pub fn lean_uint64_to_uint8(a: u64) callconv(.C) u8 {
    return @as(u8, @bitCast(@as(u8, @truncate(a))));
}
pub fn lean_uint64_to_uint16(a: u64) callconv(.C) u16 {
    return @as(u16, @bitCast(@as(c_ushort, @truncate(a))));
}
pub fn lean_uint64_to_uint32(a: u64) callconv(.C) u32 {
    return @as(u32, @bitCast(@as(c_uint, @truncate(a))));
}
pub fn lean_uint64_to_usize(a: u64) callconv(.C) usize {
    return @as(usize, @bitCast(a));
}
pub extern fn lean_usize_of_big_nat(a: b_lean_obj_arg) usize;
pub fn lean_usize_of_nat(a: b_lean_obj_arg) callconv(.C) usize {
    return if (@as(c_int, @intFromBool(lean_is_scalar(a))) != 0) lean_unbox(a) else lean_usize_of_big_nat(a);
}
pub fn lean_usize_of_nat_mk(a: lean_obj_arg) callconv(.C) usize {
    var r: usize = lean_usize_of_nat(a);
    lean_dec(a);
    return r;
}
pub fn lean_usize_add(a1: usize, a2: usize) callconv(.C) usize {
    return a1 +% a2;
}
pub fn lean_usize_sub(a1: usize, a2: usize) callconv(.C) usize {
    return a1 -% a2;
}
pub fn lean_usize_mul(a1: usize, a2: usize) callconv(.C) usize {
    return a1 *% a2;
}
pub fn lean_usize_div(a1: usize, a2: usize) callconv(.C) usize {
    return if (a2 == 0) 0 else a1 / a2;
}
pub fn lean_usize_mod(a1: usize, a2: usize) callconv(.C) usize {
    return if (a2 == 0) a1 else a1 % a2;
}
pub fn lean_usize_land(a: usize, b: usize) callconv(.C) usize {
    return a & b;
}
pub fn lean_usize_lor(a: usize, b: usize) callconv(.C) usize {
    return a | b;
}
pub fn lean_usize_xor(a: usize, b: usize) callconv(.C) usize {
    return a ^ b;
}
pub fn lean_usize_shift_left(a: usize, b: usize) callconv(.C) usize {
    return a << @intCast(b % (@sizeOf(usize) *% 8));
}
pub fn lean_usize_shift_right(a: usize, b: usize) callconv(.C) usize {
    return a >> @intCast(b % (@sizeOf(usize) *% 8));
}
pub fn lean_usize_complement(a: usize) callconv(.C) usize {
    return ~a;
}
pub extern fn lean_usize_big_modn(a1: usize, a2: b_lean_obj_arg) usize;
pub fn lean_usize_modn(a1: usize, a2: b_lean_obj_arg) callconv(.C) usize {
    if (__builtin_expect(@as(c_long, @intFromBool(lean_is_scalar(a2))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        var n2: usize = lean_unbox(a2);
        return if (n2 == 0) a1 else a1 % n2;
    } else {
        return lean_usize_big_modn(a1, a2);
    }
    return std.mem.zeroes(usize);
}
pub fn lean_usize_log2(a: usize) callconv(.C) usize {
    var res: usize = 0;
    while (a >= @as(usize, @bitCast(@as(c_long, @as(c_int, 2))))) {
        res +%= 1;
        a /= @as(usize, @bitCast(@as(c_long, @as(c_int, 2))));
    }
    return res;
}
pub fn lean_usize_dec_eq(a1: usize, a2: usize) callconv(.C) u8 {
    return @as(u8, @intFromBool(a1 == a2));
}
pub fn lean_usize_dec_lt(a1: usize, a2: usize) callconv(.C) u8 {
    return @as(u8, @intFromBool(a1 < a2));
}
pub fn lean_usize_dec_le(a1: usize, a2: usize) callconv(.C) u8 {
    return @as(u8, @intFromBool(a1 <= a2));
}
pub fn lean_usize_to_uint32(a: usize) callconv(.C) u32 {
    return @as(u32, @bitCast(@as(c_uint, @truncate(a))));
}
pub fn lean_usize_to_uint64(a: usize) callconv(.C) u64 {
    return @as(u64, @bitCast(a));
}
pub extern fn lean_float_to_string(a: f64) lean_obj_res;
pub extern fn lean_float_scaleb(a: f64, b: b_lean_obj_arg) f64;
pub extern fn lean_float_isnan(a: f64) u8;
pub extern fn lean_float_isfinite(a: f64) u8;
pub extern fn lean_float_isinf(a: f64) u8;
pub extern fn lean_float_frexp(a: f64) lean_obj_res;
pub fn lean_box_uint32(v: u32) callconv(.C) lean_obj_res {
    if (@sizeOf(*anyopaque) == @as(c_ulong, @bitCast(@as(c_long, @as(c_int, 4))))) {
        var r: lean_obj_res = lean_alloc_ctor(@as(c_uint, @bitCast(0)), @as(c_uint, @bitCast(0)), @as(c_uint, @bitCast(@as(c_uint, @truncate(@sizeOf(u32))))));
        lean_ctor_set_uint32(r, @as(c_uint, @bitCast(0)), v);
        return r;
    } else {
        return lean_box(@as(usize, @bitCast(@as(c_ulong, v))));
    }
}
pub fn lean_unbox_uint32(o: b_lean_obj_arg) callconv(.C) c_uint {
    if (@sizeOf(*anyopaque) == @as(c_ulong, @bitCast(@as(c_long, @as(c_int, 4))))) {
        return lean_ctor_get_uint32(o, @as(c_uint, @bitCast(0)));
    } else {
        return @as(c_uint, @bitCast(@as(c_uint, @truncate(lean_unbox(o)))));
    }
    return 0;
}
pub fn lean_box_uint64(v: u64) callconv(.C) lean_obj_res {
    var r: lean_obj_res = lean_alloc_ctor(@as(c_uint, @bitCast(0)), @as(c_uint, @bitCast(0)), @as(c_uint, @bitCast(@as(c_uint, @truncate(@sizeOf(u64))))));
    lean_ctor_set_uint64(r, @as(c_uint, @bitCast(0)), v);
    return r;
}
pub fn lean_unbox_uint64(o: b_lean_obj_arg) callconv(.C) u64 {
    return lean_ctor_get_uint64(o, @as(c_uint, @bitCast(0)));
}
pub fn lean_box_usize(v: usize) callconv(.C) lean_obj_res {
    var r: lean_obj_res = lean_alloc_ctor(@as(c_uint, @bitCast(0)), @as(c_uint, @bitCast(0)), @as(c_uint, @bitCast(@as(c_uint, @truncate(@sizeOf(usize))))));
    lean_ctor_set_usize(r, @as(c_uint, @bitCast(0)), v);
    return r;
}
pub fn lean_unbox_usize(o: b_lean_obj_arg) callconv(.C) usize {
    return lean_ctor_get_usize(o, @as(c_uint, @bitCast(0)));
}
pub fn lean_box_float(v: f64) callconv(.C) lean_obj_res {
    var r: lean_obj_res = lean_alloc_ctor(@as(c_uint, @bitCast(0)), @as(c_uint, @bitCast(0)), @as(c_uint, @bitCast(@as(c_uint, @truncate(@sizeOf(f64))))));
    lean_ctor_set_float(r, @as(c_uint, @bitCast(0)), v);
    return r;
}
pub fn lean_unbox_float(o: b_lean_obj_arg) callconv(.C) f64 {
    return lean_ctor_get_float(o, @as(c_uint, @bitCast(0)));
}
pub extern fn lean_dbg_trace(s: lean_obj_arg, @"fn": lean_obj_arg) LeanPtr;
pub extern fn lean_dbg_sleep(ms: u32, @"fn": lean_obj_arg) LeanPtr;
pub extern fn lean_dbg_trace_if_shared(s: lean_obj_arg, a: lean_obj_arg) LeanPtr;
pub extern fn lean_decode_io_error(errnum: c_int, fname: b_lean_obj_arg) lean_obj_res;
pub fn lean_io_mk_world() callconv(.C) lean_obj_res {
    return lean_box(0);
}
pub fn lean_io_result_is_ok(r: b_lean_obj_arg) callconv(.C) bool {
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(r)))) == 0;
}
pub fn lean_io_result_is_error(r: b_lean_obj_arg) callconv(.C) bool {
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(r)))) == @as(c_int, 1);
}
pub fn lean_io_result_get_value(r: b_lean_obj_arg) callconv(.C) b_lean_obj_res {
    assert(@src(), lean_io_result_is_ok(r), "lean_io_result_is_ok(r)");
    return lean_ctor_get(r, @as(c_uint, @bitCast(0)));
}
pub fn lean_io_result_get_error(r: b_lean_obj_arg) callconv(.C) b_lean_obj_res {
    assert(@src(), lean_io_result_is_error(r), "lean_io_result_is_error(r)");
    return lean_ctor_get(r, @as(c_uint, @bitCast(0)));
}
pub extern fn lean_io_result_show_error(r: b_lean_obj_arg) void;
pub extern fn lean_io_mark_end_initialization(...) void;
pub fn lean_io_result_mk_ok(a: lean_obj_arg) callconv(.C) lean_obj_res {
    var r: LeanPtr = lean_alloc_ctor(@as(c_uint, @bitCast(0)), @as(c_uint, @bitCast(@as(c_int, 2))), @as(c_uint, @bitCast(0)));
    lean_ctor_set(r, @as(c_uint, @bitCast(0)), a);
    lean_ctor_set(r, @as(c_uint, @bitCast(@as(c_int, 1))), lean_box(0));
    return r;
}
pub fn lean_io_result_mk_error(e: lean_obj_arg) callconv(.C) lean_obj_res {
    var r: LeanPtr = lean_alloc_ctor(@as(c_uint, @bitCast(@as(c_int, 1))), @as(c_uint, @bitCast(@as(c_int, 2))), @as(c_uint, @bitCast(0)));
    lean_ctor_set(r, @as(c_uint, @bitCast(0)), e);
    lean_ctor_set(r, @as(c_uint, @bitCast(@as(c_int, 1))), lean_box(0));
    return r;
}
pub extern fn lean_mk_io_error_already_exists(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_already_exists_file(lean_obj_arg, u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_eof(lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_hardware_fault(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_illegal_operation(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_inappropriate_type(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_inappropriate_type_file(lean_obj_arg, u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_interrupted(lean_obj_arg, u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_invalid_argument(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_invalid_argument_file(lean_obj_arg, u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_no_file_or_directory(lean_obj_arg, u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_no_such_thing(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_no_such_thing_file(lean_obj_arg, u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_other_error(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_permission_denied(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_permission_denied_file(lean_obj_arg, u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_protocol_error(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_resource_busy(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_resource_exhausted(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_resource_exhausted_file(lean_obj_arg, u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_resource_vanished(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_time_expired(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_unsatisfied_constraints(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_unsupported_operation(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_user_error(str: lean_obj_arg) lean_obj_res;
pub extern fn lean_st_mk_ref(lean_obj_arg, lean_obj_arg) lean_obj_res;
pub extern fn lean_st_ref_get(b_lean_obj_arg, lean_obj_arg) lean_obj_res;
pub extern fn lean_st_ref_set(b_lean_obj_arg, lean_obj_arg, lean_obj_arg) lean_obj_res;
pub extern fn lean_st_ref_reset(b_lean_obj_arg, lean_obj_arg) lean_obj_res;
pub extern fn lean_st_ref_swap(b_lean_obj_arg, lean_obj_arg, lean_obj_arg) lean_obj_res;
pub fn lean_ptr_addr(a: b_lean_obj_arg) callconv(.C) usize {
    return @as(usize, @intCast(@intFromPtr(a)));
}
pub extern fn lean_name_eq(n1: b_lean_obj_arg, n2: b_lean_obj_arg) u8;
pub fn lean_name_hash_ptr(n: b_lean_obj_arg) callconv(.C) u64 {
    assert(@src(), !lean_is_scalar(n), "!lean_is_scalar(n)");
    return lean_ctor_get_uint64(n, @as(c_uint, @bitCast(@as(c_uint, @truncate(@sizeOf(LeanPtr) *% @as(c_ulong, @bitCast(@as(c_long, @as(c_int, 2)))))))));
}
pub fn lean_name_hash(n: b_lean_obj_arg) callconv(.C) u64 {
    if (lean_is_scalar(n)) return @as(u64, @bitCast(@as(c_long, @as(c_int, 1723)))) else return lean_name_hash_ptr(n);
    return std.mem.zeroes(u64);
}
pub fn lean_float_to_uint8(a: f64) callconv(.C) u8 {
    return @as(u8, @bitCast(@as(i8, @truncate(if (0.0 <= a) if (a < 256.0) @as(c_int, @bitCast(@as(c_uint, @as(u8, @intFromFloat(a))))) else @as(c_int, 255) else 0))));
}
pub fn lean_float_to_uint16(a: f64) callconv(.C) u16 {
    return @as(u16, @bitCast(@as(c_short, @truncate(if (0.0 <= a) if (a < 65536.0) @as(c_int, @bitCast(@as(c_uint, @as(u16, @intFromFloat(a))))) else @as(c_int, 65535) else 0))));
}
pub fn lean_float_to_uint32(a: f64) callconv(.C) u32 {
    return if (0.0 <= a) if (a < 4294967296.0) @as(u32, @intFromFloat(a)) else @as(c_uint, 4294967295) else @as(c_uint, @bitCast(0));
}
pub fn lean_float_to_uint64(a: f64) callconv(.C) u64 {
    return if (0.0 <= a) if (a < 18446744073709550000.0) @as(u64, @intFromFloat(a)) else @as(c_ulong, 18446744073709551615) else @as(c_ulong, @bitCast(@as(c_long, 0)));
}
pub fn lean_float_to_usize(a: f64) callconv(.C) usize {
    if (@sizeOf(usize) == @sizeOf(u64)) return @as(usize, @bitCast(lean_float_to_uint64(a))) else return @as(usize, @bitCast(@as(c_ulong, lean_float_to_uint32(a))));
    return std.mem.zeroes(usize);
}
pub fn lean_float_add(a: f64, b: f64) callconv(.C) f64 {
    return a + b;
}
pub fn lean_float_sub(a: f64, b: f64) callconv(.C) f64 {
    return a - b;
}
pub fn lean_float_mul(a: f64, b: f64) callconv(.C) f64 {
    return a * b;
}
pub fn lean_float_div(a: f64, b: f64) callconv(.C) f64 {
    return a / b;
}
pub fn lean_float_negate(a: f64) callconv(.C) f64 {
    return -a;
}
pub fn lean_float_beq(a: f64, b: f64) callconv(.C) u8 {
    return @as(u8, @intFromBool(a == b));
}
pub fn lean_float_decLe(a: f64, b: f64) callconv(.C) u8 {
    return @as(u8, @intFromBool(a <= b));
}
pub fn lean_float_decLt(a: f64, b: f64) callconv(.C) u8 {
    return @as(u8, @intFromBool(a < b));
}
pub fn lean_uint64_to_float(a: u64) callconv(.C) f64 {
    return @as(f64, @floatFromInt(a));
}
pub fn lean_hashmap_mk_idx(sz: lean_obj_arg, hash: u64) callconv(.C) usize {
    return @as(usize, @bitCast(hash & (lean_unbox(sz) -% @as(usize, @bitCast(@as(c_long, @as(c_int, 1)))))));
}
pub fn lean_hashset_mk_idx(sz: lean_obj_arg, hash: u64) callconv(.C) usize {
    return @as(usize, @bitCast(hash & (lean_unbox(sz) -% @as(usize, @bitCast(@as(c_long, @as(c_int, 1)))))));
}
pub fn lean_expr_data(expr: lean_obj_arg) callconv(.C) u64 {
    return lean_ctor_get_uint64(expr, @as(c_uint, @bitCast(@as(c_uint, @truncate(@as(c_ulong, @bitCast(@as(c_ulong, lean_ctor_num_objs(expr)))) *% @sizeOf(*anyopaque))))));
}
pub fn lean_get_max_ctor_fields(_unit: lean_obj_arg) callconv(.C) lean_obj_res {
    _ = @TypeOf(_unit);
    return lean_box(@as(usize, @bitCast(@as(c_long, @as(c_int, 256)))));
}
pub fn lean_get_max_ctor_scalars_size(_unit: lean_obj_arg) callconv(.C) lean_obj_res {
    _ = @TypeOf(_unit);
    return lean_box(@as(usize, @bitCast(@as(c_long, @as(c_int, 1024)))));
}
pub fn lean_get_usize_size(_unit: lean_obj_arg) callconv(.C) lean_obj_res {
    _ = @TypeOf(_unit);
    return lean_box(@sizeOf(usize));
}
pub fn lean_get_max_ctor_tag(_unit: lean_obj_arg) callconv(.C) lean_obj_res {
    _ = @TypeOf(_unit);
    return lean_box(@as(usize, @bitCast(@as(c_long, @as(c_int, 244)))));
}
pub fn lean_strict_or(b1: u8, b2: u8) callconv(.C) u8 {
    return @as(u8, @intFromBool((@as(c_int, @bitCast(@as(c_uint, b1))) != 0) or (@as(c_int, @bitCast(@as(c_uint, b2))) != 0)));
}
pub fn lean_strict_and(b1: u8, b2: u8) callconv(.C) u8 {
    return @as(u8, @intFromBool((@as(c_int, @bitCast(@as(c_uint, b1))) != 0) and (@as(c_int, @bitCast(@as(c_uint, b2))) != 0)));
}
pub fn lean_version_get_major(_unit: lean_obj_arg) callconv(.C) lean_obj_res {
    _ = @TypeOf(_unit);
    return lean_box(@as(usize, @bitCast(@as(c_long, @as(c_int, 4)))));
}
pub fn lean_version_get_minor(_unit: lean_obj_arg) callconv(.C) lean_obj_res {
    _ = @TypeOf(_unit);
    return lean_box(0);
}
pub fn lean_version_get_patch(_unit: lean_obj_arg) callconv(.C) lean_obj_res {
    _ = @TypeOf(_unit);
    return lean_box(0);
}
pub fn lean_version_get_is_release(_unit: lean_obj_arg) callconv(.C) u8 {
    _ = @TypeOf(_unit);
    return 0;
}
pub fn lean_version_get_special_desc(_unit: lean_obj_arg) callconv(.C) lean_obj_res {
    _ = @TypeOf(_unit);
    return lean_mk_string("nightly-2023-08-26");
}
pub fn lean_internal_is_stage0(_unit: lean_obj_arg) callconv(.C) u8 {
    _ = @TypeOf(_unit);
    return 0;
}
pub fn lean_nat_pred(n: b_lean_obj_arg) callconv(.C) lean_obj_res {
    return lean_nat_sub(n, lean_box(@as(usize, @bitCast(@as(c_long, @as(c_int, 1))))));
}
pub const LEAN_VERSION_MAJOR = @as(c_int, 4);
pub const LEAN_VERSION_MINOR = 0;
pub const LEAN_VERSION_PATCH = 0;
pub const LEAN_VERSION_IS_RELEASE = 0;
pub const LEAN_IS_STAGE0 = 0;
pub const LEAN_CLOSURE_MAX_ARGS = @as(c_int, 16);
pub const LEAN_OBJECT_SIZE_DELTA = @as(c_uint, 8);
pub const LEAN_MAX_SMALL_OBJECT_SIZE = @as(c_int, 4096);
pub inline fn LEAN_UNLIKELY(x: bool) bool {
    return __builtin_expect(x, 0);
}
pub inline fn LEAN_LIKELY(x: bool) bool {
    return __builtin_expect(x, 1);
}
pub inline fn LEAN_BYTE(Var: anytype, Index: anytype) @TypeOf((std.zig.c_translation.cast([*]u8, &Var) + Index).*) {
    return (std.zig.c_translation.cast([*]u8, &Var) + Index).*;
}
pub const LeanMaxCtorTag = @as(c_int, 244);
pub const LeanClosure = @as(c_int, 245);
pub const LeanArray = @as(c_int, 246);
pub const LeanStructArray = @as(c_int, 247);
pub const LeanScalarArray = @as(c_int, 248);
pub const LeanString = @as(c_int, 249);
pub const LeanMPZ = @as(c_int, 250);
pub const LeanThunk = @as(c_int, 251);
pub const LeanTask = @as(c_int, 252);
pub const LeanRef = @as(c_int, 253);
pub const LeanExternal = @as(c_int, 254);
pub const LeanReserved = @as(c_int, 255);
pub const LEAN_MAX_CTOR_FIELDS = @as(c_int, 256);
pub const LEAN_MAX_CTOR_SCALARS_SIZE = @as(c_int, 1024);
pub const LEAN_MAX_SMALL_NAT = std.math.maxInt(c_int) >> @as(c_int, 1);
pub const LEAN_MAX_SMALL_INT = if (@sizeOf(*anyopaque) == 8) std.math.maxInt(c_int) else 1 << 30;
pub const LEAN_MIN_SMALL_INT = if (@sizeOf(*anyopaque) == 8) std.math.maxInt(c_int) else -(1 << 30);
pub const lean_task = lean_task_object;
const std = @import("std");
