#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, uprobe, uretprobe}, 
    programs::{ProbeContext, RetProbeContext},
    maps::{HashMap, Array, StackTrace},
    EbpfContext
};
use aya_log_ebpf::info;

/*-----------------------------------------------ENUMS-----------------------------------------------------*/

#[repr(u32)]
enum AllocationTypes {
    EMALLOC = 0,
    PEMALLOC = 1,
    EREALLOC = 2,
    PEREALLOC = 3,
    ECALLOC = 4,
    PECALLOC = 5,
}

#[allow(non_camel_case_types)]
#[repr(u32)]
enum MemoryCorruptionTypes {
    DOUBLE_FREE_EFREE = 0,
    DOUBLE_FREE_PEFREE = 1,
    MISMATCHED_EFREE = 2,
    MISMATCHED_PEFREE = 3,
}

/*-----------------------------------------------STRUCTS-----------------------------------------------------*/

#[repr(C)]
#[derive(Default, Copy, Clone)]
struct Allocation {
    operation: u32,
    pointer: u64,
    size: u64,
    pid: u32,
    stack_id: i64,
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
struct ReallocInfo {
    old_pointer: u64,
    size: u64,
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
struct MemoryCorruptionInfo {
    corruption_type: u32,
    pointer: u64,
    pid: u32,
    stack_id: i64,
}

/*-----------------------------------------------MAPS-----------------------------------------------------*/

#[map]
static PID_MAP: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static THREAD_IN_EXTENSION: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

#[map]
static STACK_TRACES: StackTrace = StackTrace::with_max_entries(1024, 0);

#[map]
static ALLOCATIONS: HashMap<u64, Allocation> = HashMap::with_max_entries(1024, 0);

#[map]
static CALL_PTR_CONNECTION: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

#[map]
static REALLOC_PTR_CONNECTION: HashMap<u32, ReallocInfo> = HashMap::with_max_entries(1024, 0);

#[map]
static MEMORY_CORRUPTIONS_PTR_CONNECTION: HashMap<u32, u64> = HashMap::with_max_entries(2, 0);

#[map]
static MEMORY_CORRUPTIONS: HashMap<u64, MemoryCorruptionInfo> = HashMap::with_max_entries(1024, 0);

#[map]
static FREED_POINTERS: HashMap<u64, u32> = HashMap::with_max_entries(1024, 0);

/*
calloc functions calls malloc functions in the background. To differentiate this, I added a flag (CHECK_CALLOC)
that activates when a calloc is entered. This flag allows program to ignore malloc requests during a calloc execution.
*/
#[map]
static CHECK_CALLOC: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

/*-----------------------------------------------HELPERS-----------------------------------------------------*/

fn get_stack_trace(ctx: &RetProbeContext) -> i64 {
    unsafe {
        STACK_TRACES.get_stackid(ctx, aya_ebpf::bindings::BPF_F_USER_STACK.into())
            .unwrap_or(-1)
    }
}

/*-----------------------------------------------UPROBES-----------------------------------------------------*/

#[uprobe]
pub fn uprobe_emalloc(ctx: ProbeContext) -> u32 {
    if let Some(size) = ctx.arg::<u64>(0) {
        let pid = ctx.pid();
        unsafe {
            if THREAD_IN_EXTENSION.get(&pid).is_some() {
                if CHECK_CALLOC.get(&pid).is_some() {
                    return 0;
                }
                let _ = CALL_PTR_CONNECTION.insert(&pid, &size, 0);
                info!(&ctx, "[eBPF] emalloc called with PID: {} and size: {}", pid, size);
            }
        }
        
    }

    0
}

#[uprobe]
pub fn uprobe_pemalloc(ctx: ProbeContext) -> u32 {
    if let Some(size) = ctx.arg::<u64>(0) {
        let pid = ctx.pid();
        unsafe {
            if THREAD_IN_EXTENSION.get(&pid).is_some() {
                if CHECK_CALLOC.get(&pid).is_some() {
                    return 0;
                }
                let _ = CALL_PTR_CONNECTION.insert(&pid, &size, 0);
                info!(&ctx, "[eBPF] pemalloc called with PID: {} and size: {}", pid, size);
            }
        }
    }

    0
}

#[uprobe]
pub fn uprobe_ecalloc(ctx: ProbeContext) -> u32 {
    if let Some(num) = ctx.arg::<u64>(0) {
        if let Some(count) = ctx.arg::<u64>(1) {
            let pid = ctx.pid();
            unsafe {
                if THREAD_IN_EXTENSION.get(&pid).is_some() {
                    let size = num * count;
                    let _ = CALL_PTR_CONNECTION.insert(&pid, &size, 0);
                    let _ = CHECK_CALLOC.insert(&pid, &size, 0);
                    info!(&ctx, "[eBPF] ecalloc called with PID: {} and size: {}", pid, size);
                }
            }
        }  
    }

    0
}

#[uprobe]
pub fn uprobe_pecalloc(ctx: ProbeContext) -> u32 {
    if let Some(num) = ctx.arg::<u64>(0) {
        if let Some(count) = ctx.arg::<u64>(1) {
            let pid = ctx.pid();
            unsafe {
                if THREAD_IN_EXTENSION.get(&pid).is_some() {
                    let size = num * count;
                    let _ = CALL_PTR_CONNECTION.insert(&pid, &size, 0);
                    let _ = CHECK_CALLOC.insert(&pid, &size, 0);
                    info!(&ctx, "[eBPF] pecalloc called with PID: {} and size: {}", pid, size);
                }
            }
        }  
    }

    0
}

#[uprobe]
pub fn uprobe_erealloc(ctx: ProbeContext) -> u32 {
    if let Some(ptr) = ctx.arg::<u64>(0) {
        if let Some(size) = ctx.arg::<u64>(1) {
            let pid = ctx.pid();
            unsafe {
                if THREAD_IN_EXTENSION.get(&pid).is_some() {
                    if ptr != 0 {
                        let realloc_info = ReallocInfo {
                            old_pointer: ptr,
                            size,
                        };
                        let _ = REALLOC_PTR_CONNECTION.insert(&pid, &realloc_info, 0);
                        info!(&ctx, "[eBPF] erealloc called with PID: {} and pointer: 0x{:x}, new size: {}", pid, ptr, size);
                    }
                }
            }
        }
    }

    0
}

#[uprobe]
pub fn uprobe_perealloc(ctx: ProbeContext) -> u32 {
    if let Some(ptr) = ctx.arg::<u64>(0) {
        if let Some(size) = ctx.arg::<u64>(1) {
            let pid = ctx.pid();
            unsafe {
                if THREAD_IN_EXTENSION.get(&pid).is_some() {
                    if ptr != 0 {
                        let realloc_info = ReallocInfo {
                            old_pointer: ptr,
                            size,
                        };
                        let _ = REALLOC_PTR_CONNECTION.insert(&pid, &realloc_info, 0);
                        info!(&ctx, "[eBPF] perealloc called with PID: {} and pointer: 0x{:x}, new size: {}", pid, ptr, size);
                    }
                }
            }
        }
    }
    0
}

#[uprobe]
pub fn uprobe_efree(ctx: ProbeContext) -> u32 {
    if let Some(ptr) = ctx.arg::<u64>(0) {
        let pid = ctx.pid();
        unsafe {
            if THREAD_IN_EXTENSION.get(&pid).is_some() {
                if ptr != 0 {
                    if let Some(allocation) = ALLOCATIONS.get(&ptr) {
                        if allocation.operation != AllocationTypes::EMALLOC as u32 && 
                            allocation.operation != AllocationTypes::ECALLOC as u32 &&
                            allocation.operation != AllocationTypes::EREALLOC as u32
                        {
                            let corruption_info = MemoryCorruptionInfo {
                                corruption_type: MemoryCorruptionTypes::MISMATCHED_EFREE as u32,
                                pointer: ptr,
                                pid,
                                stack_id: -1,
                            };
                            let _ = MEMORY_CORRUPTIONS.insert(&ptr, &corruption_info, 0);
                            info!(&ctx, "[eBPF] efree called with PID: {} and pointer: 0x{:x}, and mismatched efree detected", pid, ptr);
                            info!(&ctx, "[eBPF] efree called with PID: {} and pointer: 0x{:x}, and mismatched efree added", pid, ptr);
                            return 0;
                        }
                        let _ = FREED_POINTERS.insert(&ptr, &pid, 0);
                        let _ = ALLOCATIONS.remove(&ptr);
                        info!(&ctx, "[eBPF] efree called with PID: {} and pointer: 0x{:x}, size was: {}", pid, ptr, allocation.size);
                    }
                    else {
                        let _ = MEMORY_CORRUPTIONS_PTR_CONNECTION.insert(&0, &ptr, 0);
                        info!(&ctx, "[eBPF] efree called with PID: {} and pointer: 0x{:x}, and double free detected", pid, ptr);
                    }
                }
            }
        }
    }

    0
}

#[uprobe]
pub fn uprobe_pefree(ctx: ProbeContext) -> u32 {
    if let Some(ptr) = ctx.arg::<u64>(0) {
        let pid = ctx.pid();
        unsafe {
            if THREAD_IN_EXTENSION.get(&pid).is_some() {
                if ptr != 0 {
                    if let Some(allocation) = ALLOCATIONS.get(&ptr) {
                        if allocation.operation != AllocationTypes::PEMALLOC as u32 && 
                            allocation.operation != AllocationTypes::PECALLOC as u32 &&
                            allocation.operation != AllocationTypes::PEREALLOC as u32
                        {
                            let corruption_info = MemoryCorruptionInfo {
                                corruption_type: MemoryCorruptionTypes::MISMATCHED_PEFREE as u32,
                                pointer: ptr,
                                pid,
                                stack_id: -1,
                            };
                            let _ = MEMORY_CORRUPTIONS.insert(&ptr, &corruption_info, 0);
                            info!(&ctx, "[eBPF] pefree called with PID: {} and pointer: 0x{:x}, and mismatched efree detected", pid, ptr);
                            info!(&ctx, "[eBPF] pefree called with PID: {} and pointer: 0x{:x}, and mismatched efree added", pid, ptr);
                            return 0;
                        }
                        let _ = FREED_POINTERS.insert(&ptr, &pid, 0);
                        let _ = ALLOCATIONS.remove(&ptr);
                        info!(&ctx, "[eBPF] pefree called with PID: {} and pointer: 0x{:x}, size was: {}", pid, ptr, allocation.size);
                    }
                    else {
                        let corruption_info = MemoryCorruptionInfo {
                            corruption_type: MemoryCorruptionTypes::DOUBLE_FREE_PEFREE as u32,
                            pointer: ptr,
                            pid,
                            stack_id: -1,
                        };
                        let _ = MEMORY_CORRUPTIONS.insert(&ptr, &corruption_info, 0);
                        info!(&ctx, "[eBPF] pefree called with PID: {} and pointer: 0x{:x}, and double free detected", pid, ptr);
                    }
                }
            }
        }
    }

    0
}


#[uprobe]
pub fn uprobe_extension_entry(ctx: ProbeContext) -> u32 {
    
    let pid = ctx.pid();

    info!(&ctx, "[eBPF] extension entry called, current PID: {}", pid);

    unsafe {
            if let Some(pid_in_map) = PID_MAP.get_ptr_mut(0) {
            *pid_in_map = pid;
        }
    }

    let _ = THREAD_IN_EXTENSION.insert(&pid, &1, 0);

    0
}

/*-----------------------------------------------URETPROBES-----------------------------------------------------*/

#[uretprobe]
pub fn uretprobe_emalloc(ctx: RetProbeContext) -> u32 { 
    if let Some(ptr) = ctx.ret::<u64>() {      
        let pid = ctx.pid();        
        unsafe {
            if THREAD_IN_EXTENSION.get(&pid).is_some() {
                if CHECK_CALLOC.get(&pid).is_some() {
                    return 0;
                }
                if ptr != 0 {
                    if let Some(size) = CALL_PTR_CONNECTION.get(&pid) {
                        let size = *size;
                        let stack_id = get_stack_trace(&ctx);
                        let allocation = Allocation {
                            operation: AllocationTypes::EMALLOC as u32,
                            pointer: ptr,
                            size,
                            pid,
                            stack_id,
                        };
                        let _ = ALLOCATIONS.insert(&ptr, &allocation, 0);
                        let _ = CALL_PTR_CONNECTION.remove(&pid);
                        info!(&ctx, "[eBPF] emalloc return called with PID: {} and pointer: 0x{:x}, size: {}", pid, ptr, size);
                    }
                    
                }
                
            }
        }
        
    }

    0
}

#[uretprobe]
pub fn uretprobe_pemalloc(ctx: RetProbeContext) -> u32 { 
    if let Some(ptr) = ctx.ret::<u64>() {        
        let pid = ctx.pid();
        unsafe {
            if THREAD_IN_EXTENSION.get(&pid).is_some() {
                if CHECK_CALLOC.get(&pid).is_some() {
                    return 0;
                }
                if ptr != 0 {
                    if let Some(size) = CALL_PTR_CONNECTION.get(&pid) {
                        let size = *size;
                        let stack_id = get_stack_trace(&ctx);
                        let allocation = Allocation {
                            operation: AllocationTypes::PEMALLOC as u32,
                            pointer: ptr,
                            size,
                            pid,
                            stack_id,
                        };
                        let _ = ALLOCATIONS.insert(&ptr, &allocation, 0);
                        let _ = CALL_PTR_CONNECTION.remove(&pid);
                        info!(&ctx, "[eBPF] pemalloc return called with PID: {} and pointer: 0x{:x}, size: {}", pid, ptr, size);
                    }
                    
                }
            }
        }
    }

    0
}

#[uretprobe]
pub fn uretprobe_ecalloc(ctx: RetProbeContext) -> u32 {
    if let Some(ptr) = ctx.ret::<u64>() {
        let pid = ctx.pid();
        unsafe {
            if THREAD_IN_EXTENSION.get(&pid).is_some() {
                if ptr != 0 {
                    if let Some(size) = CALL_PTR_CONNECTION.get(&pid) {
                        let size = *size;
                        let stack_id = get_stack_trace(&ctx);
                        let allocation = Allocation {
                            operation: AllocationTypes::ECALLOC as u32,
                            pointer: ptr,
                            size,
                            pid,
                            stack_id,
                        };
                        let _ = ALLOCATIONS.insert(&ptr, &allocation, 0);
                        let _ = CALL_PTR_CONNECTION.remove(&pid);
                        let _ = CHECK_CALLOC.remove(&pid);
                    }
                    info!(&ctx, "[eBPF] ecalloc return called with PID: {} and pointer: 0x{:x}", pid, ptr);
                }
            }
        }
    }

    0
}

#[uretprobe]
pub fn uretprobe_pecalloc(ctx: RetProbeContext) -> u32 {
    if let Some(ptr) = ctx.ret::<u64>() {
        let pid = ctx.pid();
        unsafe {
            if THREAD_IN_EXTENSION.get(&pid).is_some() {
                if ptr != 0 {
                    if let Some(size) = CALL_PTR_CONNECTION.get(&pid) {
                        let size = *size;
                        let stack_id = get_stack_trace(&ctx);
                        let allocation = Allocation {
                            operation: AllocationTypes::PECALLOC as u32,
                            pointer: ptr,
                            size,
                            pid,
                            stack_id,
                        };
                        let _ = ALLOCATIONS.insert(&ptr, &allocation, 0);
                        let _ = CALL_PTR_CONNECTION.remove(&pid);
                        let _ = CHECK_CALLOC.remove(&pid);
                    }
                    info!(&ctx, "[eBPF] pecalloc return called with PID: {} and pointer: 0x{:x}", pid, ptr);
                }
            }
        }
    }

    0
}

#[uretprobe]
pub fn uretprobe_erealloc(ctx: RetProbeContext) -> u32 { 
    if let Some(ptr) = ctx.ret::<u64>() {
        let pid = ctx.pid();
        unsafe {
            if THREAD_IN_EXTENSION.get(&pid).is_some() {
                if let Some(realloc_info) = REALLOC_PTR_CONNECTION.get(&pid) {
                    let realloc_info = *realloc_info;
                    let old_ptr = realloc_info.old_pointer;
                    if let Some(_) = ALLOCATIONS.get(&old_ptr) {
                        let stack_id = get_stack_trace(&ctx);
                        let new_allocation = Allocation {
                            operation: AllocationTypes::EREALLOC as u32,
                            pointer: ptr,
                            size: realloc_info.size,
                            pid,
                            stack_id,
                        };
                        let _ = ALLOCATIONS.remove(&old_ptr);
                        let _ = ALLOCATIONS.insert(&ptr, &new_allocation, 0);
                        info!(&ctx, "[eBPF] erealloc called with PID: {} and old pointer: 0x{:x}, new pointer: 0x{:x}, size was: {}", pid, old_ptr, ptr, realloc_info.size);
                    }
                    let _ = REALLOC_PTR_CONNECTION.remove(&pid);
                }
            }
        }
        
    }

    0
}

#[uretprobe]
pub fn uretprobe_perealloc(ctx: RetProbeContext) -> u32 { 
    if let Some(ptr) = ctx.ret::<u64>() {
        let pid = ctx.pid();
        unsafe {
            if THREAD_IN_EXTENSION.get(&pid).is_some() {
                if let Some(realloc_info) = REALLOC_PTR_CONNECTION.get(&pid) {
                    let realloc_info = *realloc_info;
                    let old_ptr = realloc_info.old_pointer;
                    if let Some(old_allocation) = ALLOCATIONS.get(&old_ptr) {
                        let old_allocation = *old_allocation;
                        let stack_id = get_stack_trace(&ctx);
                        let new_allocation = Allocation {
                            operation: AllocationTypes::PEREALLOC as u32,
                            pointer: ptr,
                            size: realloc_info.size,
                            pid,
                            stack_id,
                        };
                        let _ = ALLOCATIONS.remove(&old_ptr);
                        let _ = ALLOCATIONS.insert(&ptr, &new_allocation, 0);
                        info!(&ctx, "[eBPF] perealloc called with PID: {} and old pointer: 0x{:x}, size was: {}", pid, old_ptr, old_allocation.size);
                    }
                    let _ = REALLOC_PTR_CONNECTION.remove(&pid);
                }
            }
        }
        
    }

    0
}

#[uretprobe]
pub fn uretprobe_efree(ctx: RetProbeContext) -> u32 {
    let pid = ctx.pid();
    unsafe {
        if THREAD_IN_EXTENSION.get(&pid).is_some() {
            if let Some(ptr) = MEMORY_CORRUPTIONS_PTR_CONNECTION.get(&0) {
                let ptr = *ptr;
                if ptr != 0 {
                    let stack_id = get_stack_trace(&ctx);
                    let memory_corruption = MemoryCorruptionInfo {
                        corruption_type: MemoryCorruptionTypes::DOUBLE_FREE_EFREE as u32,
                        pointer: ptr,
                        pid,
                        stack_id,
                    };
                    let _ = MEMORY_CORRUPTIONS_PTR_CONNECTION.remove(&0);
                    let _ = MEMORY_CORRUPTIONS.insert(&ptr, &memory_corruption, 0);
                    info!(&ctx, "[eBPF] efree return called with PID: {} and pointer: 0x{:x}, and double free added", pid, ptr);
                }
            
            }
        }
    }
    

    0
}

/*#[uretprobe]
pub fn uretprobe_pefree(ctx: RetProbeContext) -> u32 {
    let pid = ctx.pid();
    unsafe {
        if THREAD_IN_EXTENSION.get(&pid).is_some() {
            if let Some(ptr) = MEMORY_CORRUPTIONS_PTR_CONNECTION.get(&1) {
                let ptr = *ptr;
                if ptr != 0 {
                    let stack_id = get_stack_trace(&ctx);
                    let memory_corruption = MemoryCorruptionInfo {
                        corruption_type: MemoryCorruptionTypes::MISMATCHED_PEFREE as u32,
                        pointer: ptr,
                        pid,
                        stack_id,
                    };
                    let _ = MEMORY_CORRUPTIONS_PTR_CONNECTION.remove(&1);
                    let _ = MEMORY_CORRUPTIONS.insert(&ptr, &memory_corruption, 0);
                    info!(&ctx, "[eBPF] pefree return called with PID: {} and pointer: 0x{:x}, and mismatched pefree added", pid, ptr);
                }
            
            }
            info!(&ctx, "[eBPF] pefree return called with PID: {}", pid);
        }
    }
    0
}*/

#[uretprobe]
pub fn uprobe_extension_exit(ctx: RetProbeContext) -> u32 {

    let pid = ctx.pid();

    info!(&ctx, "[eBPF] extension exit called, current PID: {}", pid);

    let _ = THREAD_IN_EXTENSION.remove(&pid);

    0
}

/*-----------------------------------------------NECESSARY-----------------------------------------------------*/

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
