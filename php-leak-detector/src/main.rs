use aya::programs::UProbe;
use aya::maps::{HashMap, StackTraceMap, Array};
use aya::Pod;
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;
use tokio::time::{sleep, Duration};
use std::process::Command;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::collections::HashMap as StdHashMap;


#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: Option<i32>,

    #[clap(long, default_value = DEFAULT_EXTENSION_PATH, help = "Path to PHP extension .so file")]
    extension_path: String,

    #[clap(long, default_value = DEFAULT_PHP_PATH, help = "Path to PHP binary")]
    php_path: String,

    #[clap(long, default_value = DEFAULT_LIBC_PATH, help = "Path to libc.so")]
    libc_path: String,
}

/*-----------------------------------------------DEFINE-----------------------------------------------------*/

const DEFAULT_LIBC_PATH: &str = "/lib/x86_64-linux-gnu/libc.so.6";
const DEFAULT_PHP_PATH: &str = "/root/Tools/php/bin/php";
const DEFAULT_EXTENSION_PATH: &str = "/root/Tools/php/lib/php/extensions/debug-non-zts-20240924/emalloc_test.so";
const DEFAULT_POOL_TIME: u64 = 10;

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
unsafe impl Pod for Allocation {}

#[repr(C)]
#[derive(Default, Copy, Clone)]
struct MemoryCorruptionInfo {
    corruption_type: u32,
    pointer: u64,
    pid: u32,
    stack_id: i64,
}
unsafe impl Pod for MemoryCorruptionInfo {}

#[derive(Debug, Clone)]
struct ProcMapInfo {
    path: String,
    start_address: u64,
    end_address: u64,
    permissions: String,
    offset: u64,
}

#[derive(Default)]
struct ExtensionFunctions {
    functions_names: Vec<String>,
    functions_count: u32,
}

/*-----------------------------------------------HELPERS----------------------------------------------------*/

fn get_extension_name(path: &str) -> &str { //Gives emalloc_test
    path.rsplit('/').next().unwrap_or("").split('.').next().unwrap_or("") 
}

fn return_operation(opcode: u32) -> String {
    match opcode {
        0 => "EMALLOC".into(),
        1 => "PEMALLOC".into(),
        2 => "EREALLOC".into(),
        3 => "PEREALLOC".into(),
        4 => "ECALLOC".into(),
        5 => "PECALLOC".into(),
        _ => "UNKNOWN".into(),
    }
}

fn parse_proc_maps(pid: u32, extension_path: &str) -> anyhow::Result<Vec<ProcMapInfo>> {

    let maps_path = format!("/proc/{}/maps", pid);
    let file = File::open(&maps_path)
        .map_err(|e| anyhow::anyhow!("Failed to open {}: {}", maps_path, e))?;
    
    let reader = BufReader::new(file);
    let mut mappings = Vec::new();
    
    for line in reader.lines() {
        let line = line?;
        
        if !line.contains(extension_path) {
            continue;
        }
        
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        
        let address_range = parts[0];
        let addresses: Vec<&str> = address_range.split('-').collect();
        if addresses.len() != 2 {
            continue;
        }
        
        let start_address = u64::from_str_radix(addresses[0], 16)
            .map_err(|e| anyhow::anyhow!("Failed to parse start address: {}", e))?;
        let end_address = u64::from_str_radix(addresses[1], 16)
            .map_err(|e| anyhow::anyhow!("Failed to parse end address: {}", e))?;
        
        let permissions = parts[1].to_string();
        
        let offset = u64::from_str_radix(parts[2], 16)
            .map_err(|e| anyhow::anyhow!("Failed to parse offset: {}", e))?;
        
        let path = if parts.len() > 5 {
            parts[5..].join(" ")
            //parts[5].to_string()
        } else {
            String::new()
        };
        
        mappings.push(ProcMapInfo {
            start_address,
            end_address,
            permissions,
            offset,
            path
        });
    }
    
    if mappings.is_empty() {
        return Err(anyhow::anyhow!("Failed to found memory mappings for extension: {}", extension_path));
    }
    
    Ok(mappings)
}

fn print_memory_corruption_information(memory_corruptions: &HashMap<&aya::maps::MapData, u64, MemoryCorruptionInfo>,
    stack_traces: &StackTraceMap<&aya::maps::MapData>, pid_proc_maps: &StdHashMap<u32, Vec<ProcMapInfo>>, extension_name: &str) {
    let mut memory_corruptions_count = 0;
    let mut line_numbers: Vec<u32> = vec![];

    for memory_corruption in memory_corruptions.iter() {
        match memory_corruption {
            Ok((_ptr, memory_corruption)) => {
                let corruption_type = match memory_corruption.corruption_type {
                    0 => "DOUBLE_FREE_EFREE",
                    1 => "DOUBLE_FREE_PEFREE",
                    2 => "MISMATCHED_EFREE",
                    3 => "MISMATCHED_PEFREE",
                    _ => "UNKNOWN",
                };

                let proc_maps = match pid_proc_maps.get(&memory_corruption.pid) {
                    Some(maps) => maps,
                    None => {
                        println!("No proc maps found for PID {}", memory_corruption.pid);
                        continue;
                    }
                };

                let stack_trace = resolve_stack_trace(stack_traces, memory_corruption.stack_id, proc_maps, extension_name, 1);
               
                let parts: Vec<&str> = stack_trace.split(':').collect();

                let function_name = parts.get(0).unwrap_or(&"");
                let extension_name = parts.get(1).unwrap_or(&"");
                let line_number = parts.get(2).unwrap_or(&"");

                if line_numbers.contains(&line_number.parse::<u32>().unwrap_or(0)) {
                    continue;
                } else {
                    line_numbers.push(line_number.parse::<u32>().unwrap_or(0));
                }

                memory_corruptions_count += 1;

                if stack_trace == "" || stack_trace == "No stack trace available" {
                    println!("Memory Corruption Detected! Pointer: {:#x}, PID: {}, Type: {}",
                        memory_corruption.pointer, memory_corruption.pid, corruption_type
                    );
                } else {
                    println!("Memory Corruption Detected! Pointer: {:#x}, PID: {}, Type: {}, Function: {}, Extension: {}, Line: {}",
                        memory_corruption.pointer, memory_corruption.pid, corruption_type,
                        function_name, extension_name, line_number
                    );
                }

                
            }
            Err(e) => {
                println!("Failed to retrieve memory corruption info: {}", e);
            }
        }
    }

    if memory_corruptions_count == 0 {
        println!("No memory corruptions detected.");
    } else {
        println!("Total memory corruption(s) detected: {}", memory_corruptions_count);
    }
    
}

fn print_leak_information(allocations: &HashMap<&aya::maps::MapData, u64, Allocation>, 
    stack_traces: &StackTraceMap<&aya::maps::MapData>, pid_proc_maps: &StdHashMap<u32, Vec<ProcMapInfo>>, extension_name: &str) {
    let mut memory_leaks_count = 0;
    let mut line_numbers: Vec<u32> = vec![];
    
    for allocation in allocations.iter() {
        match allocation {
            Ok((ptr, allocation)) => {
                let proc_maps = match pid_proc_maps.get(&allocation.pid) {
                    Some(maps) => maps,
                    None => {
                        println!("No proc maps found for PID {}", allocation.pid);
                        continue;
                    }
                };
                
                let stack_trace = resolve_stack_trace(stack_traces, allocation.stack_id, proc_maps, extension_name, 0);

                if stack_trace == "" || allocation.stack_id < 0 {
                    continue;
                }

                let parts: Vec<&str> = stack_trace.split(':').collect();

                let function_name = parts.get(0).unwrap_or(&"");
                let extension_name = parts.get(1).unwrap_or(&"");
                let line_number = parts.get(2).unwrap_or(&"").split_whitespace().next().unwrap_or("");

                if line_numbers.contains(&line_number.parse::<u32>().expect("Failed to parse line number")) {
                    continue;
                } else {
                    line_numbers.push(line_number.parse::<u32>().expect("Failed to parse line number"));
                }

                memory_leaks_count += 1;

                println!(
                    "Memory Leak Detected! Pointer: {:#x}, Size: {}, PID: {}, Type: {}, Function: {}, Extension: {}, Line: {}",
                    ptr, allocation.size, allocation.pid, return_operation(allocation.operation), 
                    function_name, extension_name, line_number
                );
            }
            Err(e) => {
                println!("Failed to retrieve allocation: {}", e);
            }
        }
    }

    if memory_leaks_count == 0 {
        println!("No memory leaks detected.\n");
    } else {
        println!("Total memory leak(s) detected: {}\n", memory_leaks_count);
    }
}

fn load_extension_functions(ebpf: &mut aya::Ebpf, pid: Option<i32>, extension_path: &str) -> anyhow::Result<()> {

    let functions = get_extension_functions(extension_path);
    
    println!("Found {} functions:", functions.functions_count);
    for function in &functions.functions_names {
        println!(" - {}", function);
    }

    println!("Attaching probes to extension functions...");

    let program_extension_function_entry: &mut UProbe = ebpf.program_mut("uprobe_extension_entry").unwrap().try_into()?;
    program_extension_function_entry.load()?;

    for function_name in &functions.functions_names {
        program_extension_function_entry.attach(Some(&function_name), 0, extension_path, pid)?;
    }

    let program_extension_function_exit: &mut UProbe = ebpf.program_mut("uprobe_extension_exit").unwrap().try_into()?;
    program_extension_function_exit.load()?;

    for function_name in &functions.functions_names {
        program_extension_function_exit.attach(Some(&function_name), 0, extension_path, pid)?;
    }

    println!("Successfully attached probes to {} functions", &functions.functions_count);

    Ok(())
}

fn get_extension_functions(extension_path: &str) -> ExtensionFunctions {

    let mut functions = ExtensionFunctions::default();

    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("nm -D {} | grep -E '(zif_|zm_)'", extension_path))
        .output()
        .expect("Failed to execute command");

    /*let output = Command::new("sh")
        .arg("-c")
        .arg(format!("nm -D {} | grep zif", extension_path))
        .output()
        .expect("Failed to execute command");*/

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            let split: Vec<&str> = line.split_whitespace().collect();
            let function_name = split[2];
            functions.functions_names.push(function_name.to_string());
            functions.functions_count += 1;
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("Command failed:\n{}", stderr);
    }

    functions
}

fn load_probes(ebpf: &mut aya::Ebpf, pid: Option<i32>, php_path: &str, libc_path: &str) -> anyhow::Result<()> {

    /*----------------------------------------UPROBE----------------------------------------------*/

    let program_emalloc: &mut UProbe = ebpf.program_mut("uprobe_emalloc").unwrap().try_into()?;
    program_emalloc.load()?;
    program_emalloc.attach(Some("_emalloc"), 0, php_path, pid)?;

    let program_pemalloc: &mut UProbe = ebpf.program_mut("uprobe_pemalloc").unwrap().try_into()?;
    program_pemalloc.load()?;
    program_pemalloc.attach(Some("__zend_malloc"), 0, php_path, pid)?;

    let program_erealloc: &mut UProbe = ebpf.program_mut("uprobe_erealloc").unwrap().try_into()?;
    program_erealloc.load()?;
    program_erealloc.attach(Some("_erealloc"), 0, php_path, pid)?;

    let program_perealloc: &mut UProbe = ebpf.program_mut("uprobe_perealloc").unwrap().try_into()?;
    program_perealloc.load()?;
    program_perealloc.attach(Some("__zend_realloc"), 0, php_path, pid)?;

    let program_ecalloc: &mut UProbe = ebpf.program_mut("uprobe_ecalloc").unwrap().try_into()?;
    program_ecalloc.load()?;
    program_ecalloc.attach(Some("_ecalloc"), 0, php_path, pid)?;

    let program_pecalloc: &mut UProbe = ebpf.program_mut("uprobe_pecalloc").unwrap().try_into()?;
    program_pecalloc.load()?;
    program_pecalloc.attach(Some("__zend_calloc"), 0, php_path, pid)?;

    let program_efree: &mut UProbe = ebpf.program_mut("uprobe_efree").unwrap().try_into()?;
    program_efree.load()?;
    program_efree.attach(Some("_efree"), 0, php_path, pid)?;

    let program_pefree: &mut UProbe = ebpf.program_mut("uprobe_pefree").unwrap().try_into()?;
    program_pefree.load()?;
    program_pefree.attach(Some("free"), 0, libc_path, pid)?;

    /*----------------------------------------URETPROBE----------------------------------------------*/

    let program_emalloc_ret: &mut UProbe = ebpf.program_mut("uretprobe_emalloc").unwrap().try_into()?;
    program_emalloc_ret.load()?;
    program_emalloc_ret.attach(Some("_emalloc"), 0, php_path, pid)?;

    let program_pemalloc_ret: &mut UProbe = ebpf.program_mut("uretprobe_pemalloc").unwrap().try_into()?;
    program_pemalloc_ret.load()?;
    program_pemalloc_ret.attach(Some("__zend_malloc"), 0, php_path, pid)?;

    let program_erealloc_ret: &mut UProbe = ebpf.program_mut("uretprobe_erealloc").unwrap().try_into()?;
    program_erealloc_ret.load()?;
    program_erealloc_ret.attach(Some("_erealloc"), 0, php_path, pid)?;

    let program_perealloc_ret: &mut UProbe = ebpf.program_mut("uretprobe_perealloc").unwrap().try_into()?;
    program_perealloc_ret.load()?;
    program_perealloc_ret.attach(Some("__zend_realloc"), 0, php_path, pid)?;

    let program_ecalloc_ret: &mut UProbe = ebpf.program_mut("uretprobe_ecalloc").unwrap().try_into()?;
    program_ecalloc_ret.load()?;
    program_ecalloc_ret.attach(Some("_ecalloc"), 0, php_path, pid)?;

    let program_pecalloc_ret: &mut UProbe = ebpf.program_mut("uretprobe_pecalloc").unwrap().try_into()?;
    program_pecalloc_ret.load()?;
    program_pecalloc_ret.attach(Some("__zend_calloc"), 0, php_path, pid)?;

    let program_efree_ret: &mut UProbe = ebpf.program_mut("uretprobe_efree").unwrap().try_into()?;
    program_efree_ret.load()?;
    program_efree_ret.attach(Some("_efree"), 0, php_path, pid)?;

    /*let program_pefree_ret: &mut UProbe = ebpf.program_mut("uretprobe_pefree").unwrap().try_into()?;
    program_pefree_ret.load()?;
    program_pefree_ret.attach(Some("free"), 0, libc_path, pid)?;*/

    Ok(())
}

fn resolve_address_to_symbol(address: u64, proc_maps: &[ProcMapInfo], is_memory_corruption: u32) -> String {
    for map in proc_maps {
        if address >= map.start_address && address < map.end_address {
            if map.permissions.contains('x') {
                let runtime_offset = address - map.start_address;
                let mut file_offset = runtime_offset + map.offset;
                
                if is_memory_corruption == 1 {
                    file_offset -= 1;
                }

                let output = Command::new("addr2line")
                    .args(&["-f", "-C", "-e", &map.path, &format!("0x{:x}", file_offset)])
                    .output();

                if let Ok(output) = output {
                    if output.status.success() {
                        let addr2line_output = String::from_utf8_lossy(&output.stdout);
                        let lines: Vec<&str> = addr2line_output.trim().split('\n').collect();
                        if lines.len() >= 2 && lines[0] != "??" {
                            return format!("{}:{}", lines[0], lines[1]);
                        }
                    }
                }
            }
        }
    }
    format!("0x{:x}", address)
}

fn resolve_stack_trace(stack_traces: &StackTraceMap<&aya::maps::MapData>, 
    stack_id: i64, proc_maps: &[ProcMapInfo], extension_name: &str, is_memory_corruption: u32) -> String {

    if stack_id < 0 {
        return "No stack trace available".into();
    }

    match stack_traces.get(&(stack_id as u32), 0) {
        Ok(stck_trc) => {
            
            let all_frames: Vec<_> = stck_trc.frames().into_iter().collect();

            let traces_to_display_len = 1;
            let mut traces_to_display = String::new();

            for (i, frame) in all_frames[..traces_to_display_len].iter().enumerate() {
                
                let symbol = resolve_address_to_symbol(frame.ip, proc_maps, is_memory_corruption);
                
                if i == 0 && !symbol.contains(extension_name) {
                    return "".to_string();
                }
                
                if i > 0 {
                    traces_to_display.push_str(" -> ");
                }
                traces_to_display.push_str(&symbol);
            }

            traces_to_display

        }
        Err(_) => {
            return "Failed to retrieve stack trace".into();
        }
    }

}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/php-leak-detector"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    load_probes(&mut ebpf, opt.pid, &opt.php_path, &opt.libc_path)?;
    load_extension_functions(&mut ebpf, opt.pid, &opt.extension_path)?;

    let allocations: HashMap<_, u64, Allocation> = HashMap::try_from(
        ebpf.map("ALLOCATIONS").ok_or(anyhow::anyhow!("ALLOCATIONS map not found"))?
    )?;

    let pid_map: Array<_, u32> = Array::try_from(
        ebpf.map("PID_MAP").ok_or(anyhow::anyhow!("PID_MAP not found"))?
    )?;

    let stack_traces: StackTraceMap<_> = StackTraceMap::try_from(
        ebpf.map("STACK_TRACES").ok_or(anyhow::anyhow!("STACK_TRACES map not found"))?
    )?;

    let memory_corruptions: HashMap<_, u64, MemoryCorruptionInfo> = HashMap::try_from(
        ebpf.map("MEMORY_CORRUPTIONS").ok_or(anyhow::anyhow!("MEMORY_CORRUPTIONS map not found"))?
    )?;

    let mut pid_proc_maps: StdHashMap<u32, Vec<ProcMapInfo>> = StdHashMap::new();

    println!("Waiting for PHP process to connect...");

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    tokio::select! {
        _ = ctrl_c => {
            println!("Exiting...\n");
        }
        _ = async {
            loop {
                let current_pid = pid_map.get(&0, 0).unwrap_or(0);
                
                if current_pid != 0 && !pid_proc_maps.contains_key(&current_pid) {
                    println!("New PHP process detected: PID {}", current_pid);
                    
                    match parse_proc_maps(current_pid, get_extension_name(&opt.extension_path)) {
                        Ok(proc_maps) => {
                            pid_proc_maps.insert(current_pid, proc_maps);
                            println!("Proc maps cached for PID {}", current_pid);
                        }
                        Err(e) => {
                            println!("Failed to get proc maps for PID {}: {}", current_pid, e);
                        }
                    }
                }
                
                sleep(Duration::from_millis(DEFAULT_POOL_TIME)).await;
            }
        } => {}
    }

    print_leak_information(&allocations, &stack_traces, &pid_proc_maps, get_extension_name(&opt.extension_path));
    print_memory_corruption_information(&memory_corruptions, &stack_traces, &pid_proc_maps, get_extension_name(&opt.extension_path));

    Ok(())
}
