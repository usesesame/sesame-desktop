use mdns_sd::{ServiceDaemon, ServiceInfo};
use std::collections::HashMap;

use crate::vault::VaultResult;

const SERVICE_TYPE: &str = "_sesame-pc._tcp.local.";

pub(crate) struct Discovery {
    daemon: ServiceDaemon,
    fullname: String,
    instance: String,
    hostname: String,
    fingerprint: String,
    retrieval_port: u16,
}

impl Discovery {
    pub(crate) fn start(retrieval_port: u16, fingerprint: String) -> VaultResult<Self> {
        let daemon = ServiceDaemon::new()
            .map_err(|_| "Sesame could not start local PC discovery.".to_string())?;
        let suffix = fingerprint.get(..8).unwrap_or("local").to_string();
        let instance = format!("sesame-pc-{suffix}");
        let hostname = format!("sesame-pc-{suffix}.local.");
        let info = service_info(&instance, &hostname, retrieval_port, &fingerprint, None)?;
        let fullname = info.get_fullname().to_string();
        daemon
            .register(info)
            .map_err(|_| "Sesame could not advertise local PC discovery.".to_string())?;
        Ok(Self {
            daemon,
            fullname,
            instance,
            hostname,
            fingerprint,
            retrieval_port,
        })
    }

    pub(crate) fn hostname(&self) -> &str {
        self.hostname.trim_end_matches('.')
    }

    pub(crate) fn set_pairing_port(&self, port: Option<u16>) -> VaultResult<()> {
        let info = service_info(
            &self.instance,
            &self.hostname,
            self.retrieval_port,
            &self.fingerprint,
            port,
        )?;
        let _ = self.daemon.unregister(&self.fullname);
        self.daemon
            .register(info)
            .map_err(|_| "Sesame could not update local PC discovery.".to_string())
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

fn service_info(
    instance: &str,
    hostname: &str,
    retrieval_port: u16,
    fingerprint: &str,
    pairing_port: Option<u16>,
) -> VaultResult<ServiceInfo> {
    let mut properties = HashMap::new();
    properties.insert("v".to_string(), "1".to_string());
    properties.insert("pc".to_string(), fingerprint.to_string());
    if let Some(port) = pairing_port {
        properties.insert("pair".to_string(), port.to_string());
    }
    ServiceInfo::new(
        SERVICE_TYPE,
        instance,
        hostname,
        "",
        retrieval_port,
        properties,
    )
    .map(|info| info.enable_addr_auto())
    .map_err(|_| "Sesame could not prepare local PC discovery.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertisements_carry_only_public_routing_fields() {
        let info = service_info(
            "sesame-pc-01234567",
            "sesame-pc-01234567.local.",
            43000,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            Some(43001),
        )
        .expect("service info");
        assert_eq!(info.get_port(), 43000);
        assert_eq!(info.get_property_val_str("v"), Some("1"));
        assert_eq!(
            info.get_property_val_str("pc"),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert_eq!(info.get_property_val_str("pair"), Some("43001"));
        assert!(info.get_property_val_str("vault").is_none());
    }
}
