use std::{ffi::c_void, sync::OnceLock};

#[repr(transparent)]
struct Library(libloading::Library);

unsafe impl Send for Library {}
unsafe impl Sync for Library {}

impl std::ops::Deref for Library {
    type Target = libloading::Library;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

struct Functions<'a> {
    REXCreate: libloading::Symbol<'a, CreateFn>,
    REXDelete: libloading::Symbol<'a, DeleteFn>,
    REXGetCreatorInfo: libloading::Symbol<'a, GetCreatorInfoFn>,
    REXGetInfo: libloading::Symbol<'a, GetInfoFn>,
    REXGetInfoFromBuffer: libloading::Symbol<'a, GetInfoFromBufferFn>,
    REXGetSliceInfo: libloading::Symbol<'a, GetSliceInfoFn>,
    REXInitializeDLL: libloading::Symbol<'a, InitializeDLLFn>,
    REXRenderPreviewBatch: libloading::Symbol<'a, RenderPreviewBatchFn>,
    REXRenderSlice: libloading::Symbol<'a, RenderSliceFn>,
    REXSetOutputSampleRate: libloading::Symbol<'a, SetOutputSampleRateFn>,
    REXSetPreviewTempo: libloading::Symbol<'a, SetPreviewTempoFn>,
    REXStartPreview: libloading::Symbol<'a, StartPreviewFn>,
    REXStopPreview: libloading::Symbol<'a, StopPreviewFn>,
    REXUninitializeDLL: libloading::Symbol<'a, UninitializeDLLFn>,
}

static REX_MODULE: OnceLock<Library> = OnceLock::new();

#[cfg(target_os = "macos")]
fn rex() -> &'static Library {
    use libc::dladdr;

    REX_MODULE.get_or_init(|| {
        let mut info = libc::Dl_info {
            dli_fname: std::ptr::null(),
            dli_fbase: std::ptr::null_mut(),
            dli_sname: std::ptr::null(),
            dli_saddr: std::ptr::null_mut(),
        };
        let result = unsafe { dladdr(&REX_MODULE as *const _ as *const c_void, &mut info) };
        let self_path = unsafe { std::ffi::CStr::from_ptr(info.dli_fname) }.to_string_lossy();
        let directory = std::path::Path::new(self_path.as_ref()).parent().unwrap();
        let path = directory.join("Rex Shared Library-original");
        let full_path = std::fs::canonicalize(path).unwrap();

        unsafe { Library(libloading::Library::new(&full_path).unwrap()) }
    })
}

#[cfg(target_os = "windows")]
fn rex() -> &'static Library {
    REX_MODULE.get_or_init(|| {
        let path = "Rex Shared Library-original";

        unsafe { Library(libloading::Library::new(&path).unwrap()) }
    })
}

static FUNCTIONS: OnceLock<Functions> = OnceLock::new();

fn functions() -> &'static Functions<'static> {
    let rex = rex();
    unsafe {
        FUNCTIONS.get_or_init(|| Functions {
            REXCreate: rex.get(b"REXCreate").unwrap(),
            REXDelete: rex.get(b"REXDelete").unwrap(),
            REXGetCreatorInfo: rex.get(b"REXGetCreatorInfo").unwrap(),
            REXGetInfo: rex.get(b"REXGetInfo").unwrap(),
            REXGetInfoFromBuffer: rex.get(b"REXGetInfoFromBuffer").unwrap(),
            REXGetSliceInfo: rex.get(b"REXGetSliceInfo").unwrap(),
            REXInitializeDLL: rex.get(b"REXInitializeDLL").unwrap(),
            REXRenderPreviewBatch: rex.get(b"REXRenderPreviewBatch").unwrap(),
            REXRenderSlice: rex.get(b"REXRenderSlice").unwrap(),
            REXSetOutputSampleRate: rex.get(b"REXSetOutputSampleRate").unwrap(),
            REXSetPreviewTempo: rex.get(b"REXSetPreviewTempo").unwrap(),
            REXStartPreview: rex.get(b"REXStartPreview").unwrap(),
            REXStopPreview: rex.get(b"REXStopPreview").unwrap(),
            REXUninitializeDLL: rex.get(b"REXUninitializeDLL").unwrap(),
        })
    }
}

unsafe impl Sync for Functions<'static> {}
unsafe impl Send for Functions<'static> {}

type CreateFn = extern "C" fn(
    p: *const c_void,
    b: *const c_void,
    s: i32,
    callback_fn: *const c_void,
    user_data: *const c_void,
) -> i32;

#[no_mangle]
pub extern "C" fn REXCreate(
    handle: *const c_void,
    buffer: *const c_void,
    size: i32,
    callback_fn: *const c_void,
    user_data: *const c_void,
) -> i32 {
    (functions().REXCreate)(handle, buffer, size, callback_fn, user_data)
}

type DeleteFn = extern "C" fn(handle: *const c_void) -> i32;

#[no_mangle]
pub extern "C" fn REXDelete(handle: *const c_void) -> i32 {
    (functions().REXDelete)(handle)
}

type GetCreatorInfoFn =
    extern "C" fn(handle: *const c_void, creator_info_size: i32, info: *const c_void) -> i32;

#[no_mangle]
pub extern "C" fn REXGetCreatorInfo(
    handle: *const c_void,
    creator_info_size: i32,
    info: *const c_void,
) -> i32 {
    (functions().REXGetCreatorInfo)(handle, creator_info_size, info)
}

type GetInfoFn = extern "C" fn(handle: *const c_void, info_size: i32, info: *const c_void) -> i32;

#[no_mangle]
pub extern "C" fn REXGetInfo(handle: *const c_void, info_size: i32, info: *const c_void) -> i32 {
    (functions().REXGetInfo)(handle, info_size, info)
}

type GetInfoFromBufferFn = extern "C" fn(
    buffer_size: i32,
    buffer: *const c_void,
    info_size: i32,
    info: *const c_void,
) -> i32;

#[no_mangle]
pub extern "C" fn REXGetInfoFromBuffer(
    buffer_size: i32,
    buffer: *const c_void,
    info_size: i32,
    info: *const c_void,
) -> i32 {
    (functions().REXGetInfoFromBuffer)(buffer_size, buffer, info_size, info)
}

type GetSliceInfoFn = extern "C" fn(
    handle: *const c_void,
    slice_index: i32,
    slice_info_size: i32,
    info: *const c_void,
) -> i32;

#[no_mangle]
pub extern "C" fn REXGetSliceInfo(
    handle: *const c_void,
    slice_index: i32,
    slice_info_size: i32,
    info: *const c_void,
) -> i32 {
    (functions().REXGetSliceInfo)(handle, slice_index, slice_info_size, info)
}

type InitializeDLLFn = extern "C" fn() -> i32;

#[no_mangle]
pub extern "C" fn REXInitializeDLL() -> i32 {
    (functions().REXInitializeDLL)()
}

type RenderPreviewBatchFn = extern "C" fn(
    handle: *const c_void,
    frames_to_render: i32,
    output_buffers: *const c_void,
) -> i32;

#[no_mangle]
pub extern "C" fn REXRenderPreviewBatch(
    handle: *const c_void,
    frames_to_render: i32,
    output_buffers: *const c_void,
) -> i32 {
    (functions().REXRenderPreviewBatch)(handle, frames_to_render, output_buffers)
}

type RenderSliceFn = extern "C" fn(
    handle: *const c_void,
    index: i32,
    frame_length: i32,
    output: *const c_void,
) -> i32;

#[no_mangle]
pub extern "C" fn REXRenderSlice(
    handle: *const c_void,
    index: i32,
    frame_length: i32,
    output: *const c_void,
) -> i32 {
    (functions().REXRenderSlice)(handle, index, frame_length, output)
}

type SetOutputSampleRateFn = extern "C" fn(handle: *const c_void, sample_rate: i32) -> i32;

#[no_mangle]
pub extern "C" fn REXSetOutputSampleRate(handle: *const c_void, sample_rate: i32) -> i32 {
    (functions().REXSetOutputSampleRate)(handle, sample_rate)
}

type SetPreviewTempoFn = extern "C" fn(handle: *const c_void, tempo: i32) -> i32;

#[no_mangle]
pub extern "C" fn REXSetPreviewTempo(handle: *const c_void, tempo: i32) -> i32 {
    (functions().REXSetPreviewTempo)(handle, tempo)
}

type StartPreviewFn = extern "C" fn(handle: *const c_void) -> i32;

#[no_mangle]
pub extern "C" fn REXStartPreview(handle: *const c_void) -> i32 {
    (functions().REXStartPreview)(handle)
}

type StopPreviewFn = extern "C" fn(handle: *const c_void) -> i32;

#[no_mangle]
pub extern "C" fn REXStopPreview(handle: *const c_void) -> i32 {
    (functions().REXStopPreview)(handle)
}

type UninitializeDLLFn = extern "C" fn(handle: *const c_void);

#[no_mangle]
pub extern "C" fn REXUninitializeDLL(handle: *const c_void) {
    (functions().REXUninitializeDLL)(handle)
}

pub fn initialize() {
    // Load original lib
    functions();
}
