#![no_std]
#![no_main]

use core::mem;

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{
        hash_map::HashMap,
        lpm_trie::{Key, LpmTrie},
    },
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

#[map(name = "SUBNET_TO_COUNTRY")]
static SUBNET_TO_COUNTRY: LpmTrie<u32, u32> = LpmTrie::with_max_entries(262144, 0);

#[map(name = "IS_ALLOWED")]
static IS_ALLOWED: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[xdp]
pub fn geopacket(ctx: XdpContext) -> u32 {
    match try_geopacket(ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

pub fn try_geopacket(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { *ethhdr }.ether_type {
        EtherType::Ipv4 => (),
        _ => return Ok(xdp_action::XDP_PASS),
    };

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let src_addr = u32::from_be(unsafe { *ipv4hdr }.src_addr);
    let key: Key<u32> = Key::new(32, src_addr.to_be());

    let is_allowed: Option<&u8> = SUBNET_TO_COUNTRY
        .get(&key)
        .and_then(|country| unsafe { IS_ALLOWED.get(&country) });
    match is_allowed {
        None => Ok(xdp_action::XDP_PASS),
        Some(0) => {
            info!(&ctx, "Dropping packet from {:x}", src_addr);
            Ok(xdp_action::XDP_DROP)
        }
        Some(_) => Ok(xdp_action::XDP_PASS),
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
