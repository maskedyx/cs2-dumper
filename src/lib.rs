#![allow(dead_code)]
#![allow(unused_imports)]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::str::FromStr;
use std::sync::Mutex;

use anyhow::Result;

use log::LevelFilter;

use memflow::prelude::v1::*;

use simplelog::*;

use analysis::AnalysisResult;

pub mod analysis;
pub mod memory;
pub mod source2;

/// Global in-memory store for the most recent analysis result.
static DUMPER_STATE: Mutex<Option<AnalysisResult>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Exported C API
// ---------------------------------------------------------------------------

/// Runs the CS2 dumper and stores all results in memory.
///
/// Parameters
/// ----------
/// - `connector`      – null-terminated name of the memflow connector to use
///                      (e.g. `"qemu"`).  Pass **NULL** to use the Windows
///                      native connector (only valid on Windows).
/// - `connector_args` – extra arguments forwarded to the connector
///                      (e.g. `"map_size=0x1000"`).  Pass **NULL** for none.
/// - `process_name`   – null-terminated name of the target process.
///                      Pass **NULL** to default to `"cs2.exe"`.
///
/// Returns `1` on success, `0` on failure.  On failure the previous state,
/// if any, is left untouched.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cs2dumper_init(
    connector: *const c_char,
    connector_args: *const c_char,
    process_name: *const c_char,
) -> c_int {
    // Best-effort logger init; ignore the error if one is already active.
    let _ = TermLogger::init(
        LevelFilter::Error,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    );

    // SAFETY: caller guarantees `process_name` is a valid C string or NULL.
    let process_name: String = if process_name.is_null() {
        "cs2.exe".to_string()
    } else {
        match unsafe { CStr::from_ptr(process_name) }.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return 0,
        }
    };

    let result: Result<AnalysisResult> = (|| {
        // Parse optional connector args.
        // SAFETY: caller guarantees `connector_args` is a valid C string or NULL.
        let args: ConnectorArgs = if connector_args.is_null() {
            ConnectorArgs::default()
        } else {
            let s = unsafe { CStr::from_ptr(connector_args) }
                .to_str()
                .map_err(|e| anyhow::anyhow!("invalid connector_args: {}", e))?;
            ConnectorArgs::from_str(s)?
        };

        // Build the OS handle, using native on Windows when no connector is given.
        #[cfg(windows)]
        let mut os = if connector.is_null() {
            memflow_native::create_os(&OsArgs::default(), LibArc::default())?
        } else {
            // SAFETY: caller guarantees `connector` is a valid C string or NULL.
            let conn_name = unsafe { CStr::from_ptr(connector) }
                .to_str()
                .map_err(|e| anyhow::anyhow!("invalid connector: {}", e))?;
            Inventory::scan()
                .builder()
                .connector(conn_name)
                .args(args)
                .os("win32")
                .build()?
        };

        #[cfg(not(windows))]
        let mut os = {
            if connector.is_null() {
                return Err(anyhow::anyhow!(
                    "a connector must be specified on non-Windows platforms"
                ));
            }
            // SAFETY: caller guarantees `connector` is a valid C string or NULL.
            let conn_name = unsafe { CStr::from_ptr(connector) }
                .to_str()
                .map_err(|e| anyhow::anyhow!("invalid connector: {}", e))?;
            Inventory::scan()
                .builder()
                .connector(conn_name)
                .args(args)
                .os("win32")
                .build()?
        };

        let mut process = os.process_by_name(&process_name)?;
        analysis::analyze_all(&mut process)
    })();

    match result {
        Ok(state) => match DUMPER_STATE.lock() {
            Ok(mut lock) => {
                *lock = Some(state);
                1
            }
            Err(_) => 0,
        },
        Err(_) => 0,
    }
}

/// Looks up an offset (relative virtual address) by module and name.
///
/// Returns the RVA as a non-negative `i64`, or `-1` if not found or if
/// [`cs2dumper_init`] has not been called successfully.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cs2dumper_get_offset(
    module_name: *const c_char,
    offset_name: *const c_char,
) -> i64 {
    if module_name.is_null() || offset_name.is_null() {
        return -1;
    }

    // SAFETY: caller guarantees both pointers are valid C strings.
    let module = match unsafe { CStr::from_ptr(module_name) }.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let name = match unsafe { CStr::from_ptr(offset_name) }.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    match DUMPER_STATE.lock() {
        Ok(lock) => lock
            .as_ref()
            .and_then(|s| s.offsets.get(module))
            .and_then(|m| m.get(name))
            .map(|&rva| rva as i64)
            .unwrap_or(-1),
        Err(_) => -1,
    }
}

/// Looks up a button state address by button name.
///
/// Returns the in-process virtual address, or `0` if not found or if
/// [`cs2dumper_init`] has not been called successfully.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cs2dumper_get_button(button_name: *const c_char) -> u64 {
    if button_name.is_null() {
        return 0;
    }

    // SAFETY: caller guarantees `button_name` is a valid C string.
    let name = match unsafe { CStr::from_ptr(button_name) }.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    match DUMPER_STATE.lock() {
        Ok(lock) => lock
            .as_ref()
            .and_then(|s| s.buttons.get(name))
            .map(|&addr| addr as u64)
            .unwrap_or(0),
        Err(_) => 0,
    }
}

/// Looks up an interface address by module and interface name.
///
/// Returns the in-process virtual address, or `0` if not found or if
/// [`cs2dumper_init`] has not been called successfully.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cs2dumper_get_interface(
    module_name: *const c_char,
    interface_name: *const c_char,
) -> u64 {
    if module_name.is_null() || interface_name.is_null() {
        return 0;
    }

    // SAFETY: caller guarantees both pointers are valid C strings.
    let module = match unsafe { CStr::from_ptr(module_name) }.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let name = match unsafe { CStr::from_ptr(interface_name) }.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    match DUMPER_STATE.lock() {
        Ok(lock) => lock
            .as_ref()
            .and_then(|s| s.interfaces.get(module))
            .and_then(|m| m.get(name))
            .map(|&addr| addr as u64)
            .unwrap_or(0),
        Err(_) => 0,
    }
}

/// Looks up a schema class field's byte offset.
///
/// Returns the offset as an `i32`, or `i32::MIN` (`0x80000000`) if not found
/// or if [`cs2dumper_init`] has not been called successfully.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cs2dumper_get_schema_field_offset(
    module_name: *const c_char,
    class_name: *const c_char,
    field_name: *const c_char,
) -> i32 {
    if module_name.is_null() || class_name.is_null() || field_name.is_null() {
        return i32::MIN;
    }

    // SAFETY: caller guarantees all three pointers are valid C strings.
    let module = match unsafe { CStr::from_ptr(module_name) }.to_str() {
        Ok(s) => s,
        Err(_) => return i32::MIN,
    };
    let class = match unsafe { CStr::from_ptr(class_name) }.to_str() {
        Ok(s) => s,
        Err(_) => return i32::MIN,
    };
    let field = match unsafe { CStr::from_ptr(field_name) }.to_str() {
        Ok(s) => s,
        Err(_) => return i32::MIN,
    };

    match DUMPER_STATE.lock() {
        Ok(lock) => lock
            .as_ref()
            .and_then(|s| s.schemas.get(module))
            .and_then(|(classes, _)| classes.iter().find(|c| c.name == class))
            .and_then(|c| c.fields.iter().find(|f| f.name == field))
            .map(|f| f.offset)
            .unwrap_or(i32::MIN),
        Err(_) => i32::MIN,
    }
}

/// Serialises all held dump data to a pretty-printed JSON string.
///
/// The returned pointer is heap-allocated and **must** be freed by passing it
/// to [`cs2dumper_free_string`].  Returns **NULL** if the dumper has not been
/// initialised or if serialisation fails.
///
/// JSON structure
/// --------------
/// ```json
/// {
///   "buttons":    { "client.dll": { "<name>": <address>, … } },
///   "interfaces": { "<module>":   { "<name>": <address>, … } },
///   "offsets":    { "<module>":   { "<name>": <rva>,     … } },
///   "schemas":    { "<module>":   { "classes": […], "enums": […] } }
/// }
/// ```
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cs2dumper_dump_json() -> *mut c_char {
    let lock = match DUMPER_STATE.lock() {
        Ok(l) => l,
        Err(_) => return std::ptr::null_mut(),
    };

    let state = match lock.as_ref() {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };

    let schemas_json = build_schemas_json(&state.schemas);

    let json = match serde_json::to_string_pretty(&serde_json::json!({
        "buttons":    { "client.dll": &state.buttons },
        "interfaces": &state.interfaces,
        "offsets":    &state.offsets,
        "schemas":    schemas_json,
    })) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    match CString::new(json) {
        Ok(cs) => cs.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Frees a string previously returned by [`cs2dumper_dump_json`].
///
/// Passing **NULL** is safe and has no effect.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cs2dumper_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        // SAFETY: `ptr` was created by `CString::into_raw` in `cs2dumper_dump_json`.
        drop(unsafe { CString::from_raw(ptr) });
    }
}

/// Releases all data held in memory.
///
/// After this call every query function will return its "not found" sentinel
/// value until [`cs2dumper_init`] is called again.
#[unsafe(no_mangle)]
pub extern "C" fn cs2dumper_free() {
    if let Ok(mut lock) = DUMPER_STATE.lock() {
        *lock = None;
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn build_schemas_json(schemas: &analysis::SchemaMap) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (module, (classes, enums)) in schemas {
        map.insert(
            module.clone(),
            serde_json::json!({
                "classes": classes,
                "enums":   enums,
            }),
        );
    }
    serde_json::Value::Object(map)
}
