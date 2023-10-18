use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;

use anyhow::Context;
use aya::maps::{hash_map, lpm_trie, lpm_trie::Key};
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{debug, info, warn};
use tokio::signal::unix::{signal, SignalKind};

static BPF_ANY: u64 = 0;

/// User-space launcher and logger for Geopacket, an eBPF XDP program for geo-filtering packets
#[derive(Debug, Parser)]
struct Opt {
    /// Filename with subnet/country mappings, specified in CIDR and ISO 3166-1 alpha-2 formats, respectively, send SIGHUP to reload
    #[clap(short, long, default_value = "ips.txt")]
    geolocations_file: String,

    /// Comma-separated list of ISO 3166-1 alpha-2 country codes for which ingress packets should be dropped
    #[clap(short, long, default_value = "")]
    disallowed: String,

    /// Interface to which the XDP program should be attached
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

struct GeolocationItem {
    ip: u32,
    subnet_mask: u32,
    country_id: u32,
}

struct GeoIpInfo {
    country_ids: HashMap<String, u32>,
    ip_geolocations: Vec<GeolocationItem>,
}

impl GeoIpInfo {
    /// Fetch the integer country id assigned to the provided country code when the geolocations file is loaded.
    fn get_country_id(&self, country: &str) -> Option<u32> {
        self.country_ids.get(country).map(|x| *x)
    }

    /// Insert subnet-to-country-id mappings from `self.ip_geolocations` into the provided eBPF LPM trie map.
    fn set_ip_country_map(
        &self,
        bpf_map: &mut lpm_trie::LpmTrie<aya::maps::MapData, u32, u32>,
    ) -> Result<(), anyhow::Error> {
        for item in self.ip_geolocations.iter() {
            bpf_map.insert(
                &Key::new(item.subnet_mask, item.ip),
                item.country_id,
                BPF_ANY,
            )?;
        }

        Ok(())
    }

    /// Clear all existing mappings from the provided eBPF LPM trie map, in preparation of a new set being loaded.
    fn clear_ip_country_map(
        &self,
        bpf_map: &mut lpm_trie::LpmTrie<aya::maps::MapData, u32, u32>,
    ) -> Result<(), anyhow::Error> {
        for item in self.ip_geolocations.iter() {
            bpf_map.remove(&Key::new(item.subnet_mask, item.ip))?;
        }

        Ok(())
    }

    /// Clear all existing country code to id mappings stored in this struct.
    fn clear_country_ids(&mut self) {
        self.country_ids.clear()
    }

    /// Return an iterator over the country code to country id mappings stored in this struct.
    fn country_id_iter(&self) -> std::collections::hash_map::Iter<'_, String, u32> {
        self.country_ids.iter()
    }

    /// Get a log of country id mappings for later printing.
    fn get_country_id_log_output(&self) -> String {
        let mut country_ids = self.country_id_iter().collect::<Vec<_>>();
        let mut lines: Vec<String> = vec![];

        lines.push("country map is:".to_string());
        country_ids.sort_by(|(k1, v1), (k2, v2)| (v1, k1).cmp(&(v2, k2)));
        for (country, id) in country_ids.iter() {
            lines.push(format!("\t{}: {}", id, country));
        }

        lines.join("\n")
    }
}

/// Read subnet to country mappings from the supplied `BufRead` implementor.
///
/// This function will fail if it encounters any malformed input, as this isn't a case where it
/// seems wise to follow the part of Postel's law that regards input.
fn load_network_geolocations(reader: impl BufRead) -> Result<GeoIpInfo, anyhow::Error> {
    let mut counter: u32 = 0;
    let mut country_ids: HashMap<String, u32> = HashMap::new();
    let mut ip_geolocations: Vec<GeolocationItem> = vec![];

    for l in reader.lines() {
        let line = l.unwrap();
        let fields: Vec<&str> = line.split(' ').collect();
        let cidr: Vec<&str> = fields[0].split('/').collect();
        let country = fields[1].to_lowercase();
        let ip_addr: Ipv4Addr = cidr[0].parse()?;
        let subnet_mask: u32 = cidr[1].parse()?;

        let id: u32;
        match country_ids.get(&country) {
            Some(cid) => {
                id = *cid;
            }
            None => {
                id = counter;
                country_ids.insert(country.to_string(), counter);
                counter += 1;
            }
        };

        ip_geolocations.push(GeolocationItem {
            ip: u32::from(ip_addr).to_be(),
            subnet_mask,
            country_id: id,
        });
    }

    Ok(GeoIpInfo {
        country_ids,
        ip_geolocations,
    })
}

/// Use info from the provided `GeoIpInfo` struct to set disallowed flags in the provided eBPF map on each country specified in `disallowed`.
///
/// A `0` means ingress packets from that country should be dropped, and no key or any other value means they should be passed.
fn set_disallowed_geolocations(
    allow_map: &mut hash_map::HashMap<aya::maps::MapData, u32, u8>,
    disallowed: &Vec<String>,
    geo_ip_info: &GeoIpInfo,
) -> Result<(), anyhow::Error> {
    for country in disallowed.iter() {
        let country_id = geo_ip_info.get_country_id(country);
        if country_id.is_none() {
            continue;
        }

        allow_map.insert(country_id.unwrap(), 0, BPF_ANY)?;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let mut geo_ip_info = load_network_geolocations(BufReader::new(
        &*tokio::fs::read(&opt.geolocations_file).await?,
    ))?;

    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/geopacket"
    ))?;

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/geopacket"
    ))?;

    let mut subnet_to_country: lpm_trie::LpmTrie<_, u32, u32> =
        lpm_trie::LpmTrie::try_from(bpf.take_map("SUBNET_TO_COUNTRY").unwrap())?;
    let mut is_allowed: hash_map::HashMap<_, u32, u8> =
        hash_map::HashMap::try_from(bpf.take_map("IS_ALLOWED").unwrap())?;

    geo_ip_info.set_ip_country_map(&mut subnet_to_country)?;
    let disallowed: Vec<String> = opt
        .disallowed
        .split(",")
        .map(|s| s.to_lowercase())
        .collect();
    set_disallowed_geolocations(&mut is_allowed, &disallowed, &geo_ip_info)?;

    info!("{}", geo_ip_info.get_country_id_log_output());

    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("geopacket").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut hup = signal(SignalKind::hangup())?;
    loop {
        tokio::select! {
            _ = interrupt.recv() => {
                info!("Exiting...");
                break;
            },
            _ = hup.recv() => {
                // Signals are always hairy, but this should be safe. recv() is cancellation safe,
                // and by now the actual handler is done, so this won't step on its own toes.
                info!("Reloading IP geolocation info");
                geo_ip_info.clear_ip_country_map(&mut subnet_to_country)?;
                geo_ip_info.clear_country_ids();

                geo_ip_info = load_network_geolocations(BufReader::new(&*tokio::fs::read(&opt.geolocations_file).await?))?;
                geo_ip_info.set_ip_country_map(&mut subnet_to_country)?;
                info!("{}", geo_ip_info.get_country_id_log_output());
            },
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::BufReader;

    use crate::load_network_geolocations;

    fn ip_list() -> String {
        "23.188.0.0/24 ky\n63.136.112.0/21 ky".to_string()
    }

    #[test]
    fn test_load_network_geolocations_parses_and_matches_ips() {
        let ips = ip_list();
        let reader = BufReader::new(ips.as_bytes());
        let geo_ip_info = load_network_geolocations(reader).unwrap();

        assert!(geo_ip_info.country_ids.len() == 1);
        assert!(*geo_ip_info.country_ids.get("ky").unwrap() == 0);
        assert!(geo_ip_info.ip_geolocations.len() == 2);
        assert!(geo_ip_info.ip_geolocations[0] == (0x17BC0000, 0));
    }
}
