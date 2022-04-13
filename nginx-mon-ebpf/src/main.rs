#![no_std]
#![no_main]

use aya_bpf::{
    macros::{uprobe, map},
    programs::ProbeContext, 
    helpers::{bpf_probe_read_user, bpf_probe_read_user_str, bpf_ktime_get_boot_ns, bpf_ktime_get_ns, bpf_get_smp_processor_id}, 
    maps::{PerCpuArray, PerfEventArray}, bindings::BPF_F_CURRENT_CPU, 
};

/* 
#[repr(C)]
pub struct MonData {
    pub req_buf: PerCpuArray<Buf>,
    pub ptr: *const u8,
    pub endtime: u64
}
 
impl MonData {
    fn new(mut self, b: PerCpuArray<Buf>) {
        self.req_buf = b;
        self.ptr =0 as *const u8;
        self.endtime =0;
    }
}*/
/*
impl Default for MonData {
    fn default() -> MonData {
        MonData {
            req_buf: Buf{buf:[0; 1024]},
            ptr:0 as *const u8,
            endtime:0
        }
    }
}*/




type _Buffer=[u8; 8192];
#[repr(C)]
#[derive(Debug, Clone)]
pub struct Buf {
    pub buf: _Buffer,
}

#[map]
pub static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub static mut TIME: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);

#[map(name="REQUESTS")]
static mut REQUESTS_BUF: PerfEventArray<Buf> = PerfEventArray::with_max_entries(1024, 0);


/**
 * ngx_http_wait_request_handler -> ngx_http_create_request
 * OR
 * ngx_http_keepalive_handler -> ngx_http_create_request
 */
#[uprobe(name="ngx_http_create_request")] //progname
pub fn ngx_http_create_request(ctx: ProbeContext) -> i64 {
    match unsafe { intercept_ngx_http_create_request(ctx) } {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

use aya_log_ebpf::{debug, error, info, trace, warn};

/**
 * As there is limited stack space, it's more memory efficient 
 * to read a single field from a struct, rather than reading 
 * the whole struct and accessing the field by name.
 * struct->field->field
**/
unsafe fn p2p<T>(ptr: *const T) -> Result<*const T, i64> {
    bpf_probe_read_user(ptr as *const _ )
}

unsafe fn intercept_ngx_http_create_request(ctx: ProbeContext) -> Result<i64, i64> {
    *(TIME.get_mut(0).ok_or(0)?) = bpf_ktime_get_ns();

    let ngx_connection_t:*const u8 =  ctx.arg(0).ok_or( 0)?;
    let buffer_ptr = ngx_connection_t.offset(176);
    let ngx_buffer_t_ptr:*const u8 = p2p(buffer_ptr)?;
    let start_ptr = ngx_buffer_t_ptr.offset(32);
    let start:*const u8 = p2p(start_ptr)?; 
    //let end_ptr= start_ptr.offset(8); // size of buf
    //let _end:*const u8 = p2p(end_ptr)?;
    
    //let start = 0x5555556cce90 as *const u8;

    let buf = BUF.get_mut(0).ok_or(0)?;
    let _len = bpf_probe_read_user_str(start, &mut buf.buf)?;
    REQUESTS_BUF.output(&ctx, buf,BPF_F_CURRENT_CPU as u32);

    Ok(0)
}
/**
 * End of processing request:
 * ngx_http_finalize_connection -> (not all cases described)
 * -> ngx_http_close_request -> ngx_http_close_connection
 * -> ngx_http_set_keepalive -> return; (timer) -> ngx_http_close_connection
 * -> ngx_http_set_keepalive -> ngx_http_close_connection  
 **/ 



#[uprobe(name="ngx_http_finalize_connection")] //progname
pub fn ngx_http_finalize_connection(ctx: ProbeContext) -> i64 {
    match unsafe { intercept_ngx_http_finalize_connection(ctx) } {
        Ok(_) => 0,
        Err(ret) => ret,
    }
}

unsafe fn intercept_ngx_http_finalize_connection(ctx: ProbeContext) -> Result<i64, i64> {'
    let second_call=  TIME.get_mut(1).ok_or(0)?;
    if *second_call == 0 { // we need call after ngx_http_upstream_handler
        *second_call = 1;
        return Ok(0);
    }
    let elapsed = bpf_ktime_get_ns() - *TIME.get_mut(0).ok_or(0)?;
    info!(&ctx, "Latency of request: {}\n", elapsed);
    *second_call=0;
    Ok(0)
}














#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
