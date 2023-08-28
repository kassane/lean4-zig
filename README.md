# lean4_zig [WiP]

Zig bindings for Lean4's C API.

Functions and comments manually translated from those in the [`lean.h` header](https://github.com/leanprover/lean4/blob/master/src/include/lean/lean.h) provided with Lean 4

### Required

- [zig](https://ziglang.org/download/) v0.11.0 or master
- [lean4](https://leanprover.github.io/download/) v4.0.0-rc or nightly


### How to run

```bash
# default: reverse ffi (lean4 lib => zig app)
$> zig build run
# output: 6
```
