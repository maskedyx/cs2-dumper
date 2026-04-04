# cs2_dumper – DLL API

`cs2_dumper.dll` exposes a plain C interface so any language that supports
FFI (C, C++, Python, C#, etc.) can attach to the CS2 process, run the full
analysis, and query the results in memory — without touching the file system.

---

## Building the DLL

```
cargo build --release --lib
```

The output is placed at:

```
target/release/cs2_dumper.dll   (Windows)
target/release/libcs2_dumper.so (Linux)
```

> **Note** – the Windows native memflow connector is used automatically when
> no connector name is supplied.  On Linux you must specify a connector.

---

## C header (`cs2_dumper.h`)

Copy this header into your project:

```c
#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialise the dumper by attaching to the target process and running the
 * full analysis.  Results are stored in memory inside the DLL.
 *
 * @param connector      memflow connector name (e.g. "qemu"), or NULL to use
 *                       the Windows native connector.
 * @param connector_args Extra connector arguments (e.g. "map_size=0x1000"),
 *                       or NULL for none.
 * @param process_name   Target process name, or NULL to default to "cs2.exe".
 * @return               1 on success, 0 on failure.
 */
int32_t cs2dumper_init(const char* connector,
                       const char* connector_args,
                       const char* process_name);

/**
 * Return the RVA of a named offset in a given module.
 *
 * @return RVA (>= 0) on success, -1 if not found / not initialised.
 */
int64_t cs2dumper_get_offset(const char* module_name,
                              const char* offset_name);

/**
 * Return the in-process address of a named button's state field.
 *
 * @return Address on success, 0 if not found / not initialised.
 */
uint64_t cs2dumper_get_button(const char* button_name);

/**
 * Return the in-process address of a named interface inside a module.
 *
 * @return Address on success, 0 if not found / not initialised.
 */
uint64_t cs2dumper_get_interface(const char* module_name,
                                  const char* interface_name);

/**
 * Return the byte offset of a field within a schema class.
 *
 * @return Field offset on success, INT32_MIN (0x80000000) if not found /
 *         not initialised.
 */
int32_t cs2dumper_get_schema_field_offset(const char* module_name,
                                           const char* class_name,
                                           const char* field_name);

/**
 * Serialise all held data to a heap-allocated, null-terminated JSON string.
 *
 * The returned pointer MUST be freed by passing it to cs2dumper_free_string().
 *
 * @return JSON string on success, NULL if not initialised or on error.
 *
 * JSON layout:
 * {
 *   "buttons":    { "client.dll": { "<name>": <address>, … } },
 *   "interfaces": { "<module>":   { "<name>": <address>, … } },
 *   "offsets":    { "<module>":   { "<name>": <rva>,     … } },
 *   "schemas":    { "<module>":   { "classes": […], "enums": […] } }
 * }
 */
const char* cs2dumper_dump_json(void);

/**
 * Free a string returned by cs2dumper_dump_json().
 * Passing NULL is safe and has no effect.
 */
void cs2dumper_free_string(char* ptr);

/**
 * Release all data held in memory.
 * After this call every query function returns its "not found" sentinel until
 * cs2dumper_init() is called again.
 */
void cs2dumper_free(void);

#ifdef __cplusplus
}
#endif
```

---

## Sentinel / error values

| Function                        | Not found / not initialised |
|---------------------------------|-----------------------------|
| `cs2dumper_get_offset`          | `-1`                        |
| `cs2dumper_get_button`          | `0`                         |
| `cs2dumper_get_interface`       | `0`                         |
| `cs2dumper_get_schema_field_offset` | `INT32_MIN` (`0x80000000`) |
| `cs2dumper_dump_json`           | `NULL`                      |

---

## Example – C++

```cpp
#include <windows.h>
#include <cstdio>
#include "cs2_dumper.h"

int main() {
    HMODULE dll = LoadLibraryA("cs2_dumper.dll");

    auto init        = (decltype(&cs2dumper_init))       GetProcAddress(dll, "cs2dumper_init");
    auto get_offset  = (decltype(&cs2dumper_get_offset)) GetProcAddress(dll, "cs2dumper_get_offset");
    auto get_field   = (decltype(&cs2dumper_get_schema_field_offset))
                           GetProcAddress(dll, "cs2dumper_get_schema_field_offset");
    auto dump_json   = (decltype(&cs2dumper_dump_json))  GetProcAddress(dll, "cs2dumper_dump_json");
    auto free_string = (decltype(&cs2dumper_free_string))GetProcAddress(dll, "cs2dumper_free_string");
    auto free_all    = (decltype(&cs2dumper_free))       GetProcAddress(dll, "cs2dumper_free");

    // NULL = Windows native connector / default process name "cs2.exe"
    if (!init(nullptr, nullptr, nullptr)) {
        puts("cs2dumper_init failed");
        return 1;
    }

    // Query a single offset
    int64_t dw_local_player = get_offset("client.dll", "dwLocalPlayerPawn");
    printf("dwLocalPlayerPawn = 0x%llX\n", dw_local_player);

    // Query a schema field
    int32_t health_off = get_field("client.dll", "C_BaseEntity", "m_iHealth");
    printf("C_BaseEntity::m_iHealth = 0x%X\n", health_off);

    // Get everything as JSON
    const char* json = dump_json();
    if (json) {
        puts(json);
        free_string(const_cast<char*>(json));
    }

    free_all();
    FreeLibrary(dll);
    return 0;
}
```

---

## Example – Python (ctypes)

```python
import ctypes, json

dll = ctypes.CDLL("cs2_dumper.dll")

# Declare signatures
dll.cs2dumper_init.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
dll.cs2dumper_init.restype  = ctypes.c_int32

dll.cs2dumper_get_offset.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
dll.cs2dumper_get_offset.restype  = ctypes.c_int64

dll.cs2dumper_get_button.argtypes = [ctypes.c_char_p]
dll.cs2dumper_get_button.restype  = ctypes.c_uint64

dll.cs2dumper_get_interface.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
dll.cs2dumper_get_interface.restype  = ctypes.c_uint64

dll.cs2dumper_get_schema_field_offset.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
dll.cs2dumper_get_schema_field_offset.restype  = ctypes.c_int32

dll.cs2dumper_dump_json.argtypes = []
dll.cs2dumper_dump_json.restype  = ctypes.c_char_p   # caller must free via cs2dumper_free_string

dll.cs2dumper_free_string.argtypes = [ctypes.c_char_p]
dll.cs2dumper_free_string.restype  = None

dll.cs2dumper_free.argtypes = []
dll.cs2dumper_free.restype  = None

# Initialise (None = Windows native connector + default process name)
if not dll.cs2dumper_init(None, None, None):
    raise RuntimeError("cs2dumper_init failed")

# Query a single offset
offset = dll.cs2dumper_get_offset(b"client.dll", b"dwLocalPlayerPawn")
print(f"dwLocalPlayerPawn = {hex(offset)}")

# Query a schema field
health = dll.cs2dumper_get_schema_field_offset(b"client.dll", b"C_BaseEntity", b"m_iHealth")
print(f"C_BaseEntity::m_iHealth = {hex(health)}")

# Dump everything as JSON
# NOTE: cs2dumper_dump_json returns a pointer owned by the DLL.
#       Use a void* restype so ctypes does not intern the string,
#       then decode and free manually.
dll.cs2dumper_dump_json.restype = ctypes.c_void_p
raw = dll.cs2dumper_dump_json()
if raw:
    text = ctypes.string_at(raw).decode()
    dll.cs2dumper_free_string.argtypes = [ctypes.c_void_p]
    dll.cs2dumper_free_string(raw)
    data = json.loads(text)
    print(json.dumps(data, indent=2))

dll.cs2dumper_free()
```

---

## Example – C\# (P/Invoke)

```csharp
using System;
using System.Runtime.InteropServices;
using System.Text.Json;

static class Cs2Dumper
{
    const string DLL = "cs2_dumper";

    [DllImport(DLL)] static extern int    cs2dumper_init(string? connector, string? args, string? process);
    [DllImport(DLL)] static extern long   cs2dumper_get_offset(string module, string name);
    [DllImport(DLL)] static extern ulong  cs2dumper_get_button(string name);
    [DllImport(DLL)] static extern ulong  cs2dumper_get_interface(string module, string name);
    [DllImport(DLL)] static extern int    cs2dumper_get_schema_field_offset(string module, string cls, string field);
    [DllImport(DLL)] static extern IntPtr cs2dumper_dump_json();
    [DllImport(DLL)] static extern void   cs2dumper_free_string(IntPtr ptr);
    [DllImport(DLL)] static extern void   cs2dumper_free();

    static void Main()
    {
        if (cs2dumper_init(null, null, null) == 0)
            throw new Exception("cs2dumper_init failed");

        long offset = cs2dumper_get_offset("client.dll", "dwLocalPlayerPawn");
        Console.WriteLine($"dwLocalPlayerPawn = 0x{offset:X}");

        int health = cs2dumper_get_schema_field_offset("client.dll", "C_BaseEntity", "m_iHealth");
        Console.WriteLine($"C_BaseEntity::m_iHealth = 0x{health:X}");

        IntPtr ptr = cs2dumper_dump_json();
        if (ptr != IntPtr.Zero)
        {
            string json = Marshal.PtrToStringUTF8(ptr)!;
            cs2dumper_free_string(ptr);
            Console.WriteLine(JsonSerializer.Serialize(
                JsonSerializer.Deserialize<object>(json),
                new JsonSerializerOptions { WriteIndented = true }));
        }

        cs2dumper_free();
    }
}
```

---

## Thread safety

All exported functions acquire an internal `Mutex` before accessing or
mutating state.  It is safe to call query functions from multiple threads
simultaneously **after** `cs2dumper_init` returns.  Do not call
`cs2dumper_init` or `cs2dumper_free` while other threads are still querying.

---

## Memory ownership

| Pointer source          | Who frees it                        |
|-------------------------|-------------------------------------|
| `cs2dumper_dump_json()` | **Caller**, via `cs2dumper_free_string()` |
| All other return values | N/A — they are plain integers        |

Never pass a pointer from `cs2dumper_dump_json` to the C runtime `free()` or
any allocator other than `cs2dumper_free_string` — the string is allocated by
Rust's allocator.
