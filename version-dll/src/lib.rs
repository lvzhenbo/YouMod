use std::ffi::c_void;
use std::sync::LazyLock;
use windows::Win32::Foundation::{HINSTANCE, HMODULE};
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows::Win32::System::LibraryLoader::{
    DisableThreadLibraryCalls, GetModuleHandleA, GetProcAddress, LoadLibraryW,
};
use windows::Win32::System::Memory::{PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VirtualProtect};
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
};
use windows::core::{BOOL, PSTR, PWSTR};

const FUSE_SENTINEL_LENGTH: usize = 32;
const FUSE_VERSION_SUPPORTED: u8 = 1;
const FUSE_MIN_WIRE_LENGTH: usize = 5;
const FUSE_ASAR_INTEGRITY_VALIDATION: usize = 4;

const SENTINEL_PART1: u64 = 0x6E64474B70374C64;
const SENTINEL_PART2: u64 = 0x6262503639377A4E;
const SENTINEL_PART3: u64 = 0x58486D4B4E57516A;
const SENTINEL_PART4: u64 = 0x5873743942615A42;

fn load_original_version_dll() -> Option<usize> {
    let mut path = [0u16; 260];
    let len = unsafe { GetSystemDirectoryW(Some(&mut path)) } as usize;
    if len == 0 || len >= 260 {
        return None;
    }
    let suffix = "\\version.dll\0".encode_utf16().collect::<Vec<u16>>();
    let remaining = 260 - len;
    if suffix.len() > remaining {
        return None;
    }
    path[len..len + suffix.len()].copy_from_slice(&suffix);
    let handle = unsafe { LoadLibraryW(PWSTR(path.as_mut_ptr())) };
    handle.ok().map(|h| h.0 as usize)
}

static ORIGINAL_VERSION_DLL: LazyLock<Option<usize>> = LazyLock::new(load_original_version_dll);

fn get_original_proc(name: &str) -> Option<unsafe extern "system" fn() -> isize> {
    let h = (*ORIGINAL_VERSION_DLL)?;
    let hmodule = HMODULE(h as *mut c_void);
    let name_bytes = format!("{}\0", name);
    let name_ptr = PSTR(name_bytes.as_ptr() as *mut u8);
    unsafe { GetProcAddress(hmodule, name_ptr) }
}

macro_rules! forward_function {
    ($name:ident, $ret:ty, $default:expr, $($arg:ident : $arg_ty:ty),*) => {
        #[unsafe(no_mangle)]
        #[allow(non_snake_case)]
        extern "system" fn $name($($arg: $arg_ty),*) -> $ret {
            static FN_PTR: std::sync::LazyLock<Option<unsafe extern "system" fn($($arg_ty),*) -> $ret>> =
                std::sync::LazyLock::new(|| {
                    $crate::get_original_proc(stringify!($name))
                        .map(|f| unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, unsafe extern "system" fn($($arg_ty),*) -> $ret>(f) })
                });
            if let Some(f) = *FN_PTR {
                unsafe { f($($arg),*) }
            } else {
                unsafe {
                    windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::ERROR_PROC_NOT_FOUND);
                }
                $default
            }
        }
    };
    ($name:ident, $ret:ty, $($arg:ident : $arg_ty:ty),*) => {
        forward_function!($name, $ret, Default::default(), $($arg: $arg_ty),*);
    };
}

#[allow(non_snake_case, non_camel_case_types)]
mod forwards {
    use windows::core::{BOOL, PCSTR, PCWSTR, PSTR, PWSTR};

    forward_function!(GetFileVersionInfoA, BOOL, BOOL(0), filename: PCSTR, handle: u32, length: u32, data: *mut std::ffi::c_void);
    forward_function!(GetFileVersionInfoExA, BOOL, BOOL(0), flags: u32, filename: PCSTR, handle: u32, length: u32, data: *mut std::ffi::c_void);
    forward_function!(GetFileVersionInfoExW, BOOL, BOOL(0), flags: u32, filename: PCWSTR, handle: u32, length: u32, data: *mut std::ffi::c_void);
    forward_function!(GetFileVersionInfoSizeA, u32, 0u32, filename: PCSTR, handle: *mut u32);
    forward_function!(GetFileVersionInfoSizeExA, u32, 0u32, flags: u32, filename: PCSTR, handle: *mut u32);
    forward_function!(GetFileVersionInfoSizeExW, u32, 0u32, flags: u32, filename: PCWSTR, handle: *mut u32);
    forward_function!(GetFileVersionInfoSizeW, u32, 0u32, filename: PCWSTR, handle: *mut u32);
    forward_function!(GetFileVersionInfoW, BOOL, BOOL(0), filename: PCWSTR, handle: u32, length: u32, data: *mut std::ffi::c_void);
    forward_function!(VerFindFileA, u32, 0u32, flags: u32, fileName: PCSTR, winDir: PCSTR, appDir: PCSTR, curDir: PSTR, curDirLen: *mut u32, destDir: PSTR, destDirLen: *mut u32);
    forward_function!(VerFindFileW, u32, 0u32, flags: u32, fileName: PCWSTR, winDir: PCWSTR, appDir: PCWSTR, curDir: PWSTR, curDirLen: *mut u32, destDir: PWSTR, destDirLen: *mut u32);
    forward_function!(VerInstallFileA, u32, 0u32, flags: u32, srcFileName: PCSTR, destFileName: PCSTR, srcDir: PCSTR, destDir: PCSTR, curDir: PCSTR, tempFile: PSTR, tempFileLen: *mut u32);
    forward_function!(VerInstallFileW, u32, 0u32, flags: u32, srcFileName: PCWSTR, destFileName: PCWSTR, srcDir: PCWSTR, destDir: PCWSTR, curDir: PCWSTR, tempFile: PWSTR, tempFileLen: *mut u32);
    forward_function!(VerLanguageNameA, u32, 0u32, language: u32, buffer: PSTR, bufferLength: u32);
    forward_function!(VerLanguageNameW, u32, 0u32, language: u32, buffer: PWSTR, bufferLength: u32);
    forward_function!(VerQueryValueA, BOOL, BOOL(0), block: *const std::ffi::c_void, subBlock: PCSTR, buffer: *mut *mut std::ffi::c_void, bufferLength: *mut u32);
    forward_function!(VerQueryValueW, BOOL, BOOL(0), block: *const std::ffi::c_void, subBlock: PCWSTR, buffer: *mut *mut std::ffi::c_void, bufferLength: *mut u32);

    #[unsafe(no_mangle)]
    #[allow(non_snake_case)]
    extern "system" fn GetFileVersionInfoByHandle() -> BOOL {
        unsafe {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(120));
        }
        BOOL(0)
    }
}

fn find_fuse_wire(base: usize, size_of_image: usize, offset: isize) -> Option<*const u8> {
    // Safety: caller must ensure base points to a valid PE image and size_of_image is correct.
    debug_assert!(base > 0, "find_fuse_wire: base address is null");
    debug_assert!(
        size_of_image >= FUSE_SENTINEL_LENGTH,
        "find_fuse_wire: image too small for sentinel"
    );

    #[inline]
    fn align8(ptr: usize, modifier: isize) -> usize {
        ((ptr + 7) & !7).wrapping_add((modifier * 8) as usize)
    }

    let start = align8(base, 1).wrapping_add(offset as usize);
    let end = align8(base + size_of_image - FUSE_SENTINEL_LENGTH, -1).wrapping_sub(offset as usize);

    // If the computed range is empty or wraps around, bail out
    if start >= end || start < base || end > base.wrapping_add(size_of_image) {
        return None;
    }

    unsafe {
        let mut p = start as *const u64;
        // Ensure room for all 4 sentinel u64 reads (p through p+3 = 32 bytes)
        let scan_limit = end.saturating_sub(3 * size_of::<u64>());
        while (p as usize) <= scan_limit {
            if *p == SENTINEL_PART1
                && *p.add(1) == SENTINEL_PART2
                && *p.add(2) == SENTINEL_PART3
                && *p.add(3) == SENTINEL_PART4
            {
                return Some(p as *const u8);
            }
            p = p.add(1);
        }
        None
    }
}

fn disable_asar_integrity() -> bool {
    let base = unsafe { GetModuleHandleA(None) }.unwrap_or(HMODULE(std::ptr::null_mut()));
    if base.0.is_null() {
        return false;
    }

    let dos_header = base.0 as *const IMAGE_DOS_HEADER;
    unsafe {
        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            return false;
        }
    }

    let nt_header =
        unsafe { (base.0 as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64 };

    unsafe {
        if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
            return false;
        }
    }

    let size_of_image = unsafe { (*nt_header).OptionalHeader.SizeOfImage } as usize;

    let wire = find_fuse_wire(base.0 as usize, size_of_image, 0)
        .or_else(|| find_fuse_wire(base.0 as usize, size_of_image, 4));

    let Some(wire) = wire else {
        return false;
    };

    unsafe {
        let version = *wire.add(FUSE_SENTINEL_LENGTH);
        if version != FUSE_VERSION_SUPPORTED {
            return false;
        }

        let wire_length = *wire.add(FUSE_SENTINEL_LENGTH + 1);
        if (wire_length as usize) < FUSE_MIN_WIRE_LENGTH {
            return true;
        }

        let target = wire.add(FUSE_SENTINEL_LENGTH + 2 + FUSE_ASAR_INTEGRITY_VALIDATION) as *mut u8;

        if *target == b'r' {
            return true;
        }

        let mut old_protect = PAGE_PROTECTION_FLAGS::default();
        if VirtualProtect(target as *const c_void, 1, PAGE_READWRITE, &mut old_protect).is_err() {
            return false;
        }

        *target = b'r';

        let _ = VirtualProtect(
            target as *const c_void,
            1,
            old_protect,
            &mut PAGE_PROTECTION_FLAGS::default(),
        );

        true
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
extern "system" fn DllMain(hinstDLL: HINSTANCE, fdwReason: u32, _lpvReserved: *mut c_void) -> BOOL {
    if fdwReason == DLL_PROCESS_ATTACH {
        unsafe {
            DisableThreadLibraryCalls(HMODULE(hinstDLL.0)).ok();
        }
        disable_asar_integrity();
    }
    BOOL::from(true)
}
