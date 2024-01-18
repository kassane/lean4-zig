# lean4-zig

Zig bindings for Lean4's C API.

Functions and comments manually translated from those in the [`lean.h` header](https://github.com/leanprover/lean4/blob/master/src/include/lean/lean.h) provided with Lean 4

### Required

- [zig](https://ziglang.org/download/) v0.12.0 or master
- [lean4](https://leanprover.github.io/download/) v4.4.0 or nightly


### How to run

- **FFI**
```bash
# default: reverse ffi (zig lib => lean4 app)
$> zig build zffi
# output: 3
```

- **Reverse-FFI**
```bash
# default: reverse ffi (lean4 lib => zig app)
$> zig build rffi
# output: 6
```
