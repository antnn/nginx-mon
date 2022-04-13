use aya::{include_bytes_aligned, Bpf};
use aya::programs::UProbe;
use aya_log::BpfLogger;
use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use structopt::StructOpt;
use tokio::signal;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long)]
    pid: Option<i32>
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();
    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/nginx-mon"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/nginx-mon"
    ))?;

    // Will log using the default logger, which is TermLogger in this case
    BpfLogger::init(&mut bpf).unwrap();
    let function_name = "ngx_http_create_request";
    let program: &mut UProbe = bpf.program_mut(function_name).unwrap().try_into()?;
    program.load()?;
    program.attach( Some(function_name), 0, "/usr/sbin/nginx", None)?;

    
    let function_name="ngx_http_finalize_connection"; //0x73d90
    let program: &mut UProbe = bpf.program_mut(function_name).unwrap().try_into()?;
    program.load()?;
    /*
     * In case of STATIC func, run:
     *    gdb -q -ex 'p &ngx_http_finalize_connection' -ex q  /usr/sbin/nginx
    */
    program.attach( None, 0x73d90, "/usr/sbin/nginx", None)?;



    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
