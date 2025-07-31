use crate::{Error, Result};
use std::io::{Read, Write};
use std::net::TcpStream;

/// TLS protocol versions
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    Tls10 = 0x0301,
    Tls11 = 0x0302,
    Tls12 = 0x0303,
    Tls13 = 0x0304,
}

impl TlsVersion {
    pub fn as_u16(&self) -> u16 {
        *self as u16
    }
    
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0301 => Some(TlsVersion::Tls10),
            0x0302 => Some(TlsVersion::Tls11),
            0x0303 => Some(TlsVersion::Tls12),
            0x0304 => Some(TlsVersion::Tls13),
            _ => None,
        }
    }
    
    pub fn as_str(&self) -> &'static str {
        match self {
            TlsVersion::Tls10 => "TLSv1.0",
            TlsVersion::Tls11 => "TLSv1.1",
            TlsVersion::Tls12 => "TLSv1.2",
            TlsVersion::Tls13 => "TLSv1.3",
        }
    }
    
    pub fn is_secure(&self) -> bool {
        *self >= TlsVersion::Tls12
    }
    
    pub fn as_bytes(&self) -> [u8; 2] {
        let value = self.as_u16();
        [(value >> 8) as u8, value as u8]
    }
}

/// Cipher suite information
#[derive(Debug, Clone)]
pub struct CipherSuite {
    pub id: u16,
    pub name: String,
    pub key_exchange: KeyExchangeAlgorithm,
    pub authentication: AuthenticationAlgorithm,
    pub encryption: EncryptionAlgorithm,
    pub mac: MacAlgorithm,
    pub security_level: SecurityLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchangeAlgorithm {
    RSA,
    ECDHE,
    DHE,
    PSK,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationAlgorithm {
    RSA,
    ECDSA,
    DSA,
    PSK,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    AES128GCM,
    AES256GCM,
    AES128CBC,
    AES256CBC,
    ChaCha20Poly1305,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacAlgorithm {
    SHA256,
    SHA384,
    AEAD,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    Weak,
    Medium,
    Strong,
    VeryStrong,
}

/// Certificate formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateFormat {
    PEM,
    DER,
    PKCS12,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    PEM,
    DER,
    PKCS8,
    PKCS1RSA,
    PKCS1EC,
}

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub verify_certificates: bool,
    pub accept_invalid_hostnames: bool,
    pub accept_invalid_certs: bool,
    pub ca_certs: Vec<Vec<u8>>,
    pub client_cert: Option<ClientCertificate>,
    pub supported_versions: Vec<TlsVersion>,
    pub cipher_suites: Vec<u16>,
    pub min_protocol_version: TlsVersion,
    pub max_protocol_version: TlsVersion,
    pub enable_sni: bool,
    pub enable_alpn: bool,
    pub alpn_protocols: Vec<String>,
    pub session_cache_size: usize,
    pub session_timeout: std::time::Duration,
    pub enable_ocsp_stapling: bool,
    pub enable_sct: bool, // Certificate Transparency
}

impl TlsConfig {
    pub fn new() -> Self {
        TlsConfig {
            verify_certificates: true,
            accept_invalid_hostnames: false,
            accept_invalid_certs: false,
            ca_certs: Vec::new(),
            client_cert: None,
            supported_versions: vec![TlsVersion::Tls12, TlsVersion::Tls13],
            cipher_suites: vec![
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0x1303, // TLS_CHACHA20_POLY1305_SHA256
                0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            ],
            min_protocol_version: TlsVersion::Tls12,
            max_protocol_version: TlsVersion::Tls13,
            enable_sni: true,
            enable_alpn: true,
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            session_cache_size: 1000,
            session_timeout: std::time::Duration::from_secs(3600), // 1 hour
            enable_ocsp_stapling: true,
            enable_sct: true,
        }
    }
    
    /// Create a secure config with only strong ciphers
    pub fn secure() -> Self {
        let mut config = Self::new();
        config.cipher_suites = vec![
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
            0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        ];
        config
    }
    
    /// Create a compatible config for older systems
    pub fn compatible() -> Self {
        let mut config = Self::new();
        config.supported_versions = vec![
            TlsVersion::Tls10,
            TlsVersion::Tls11,
            TlsVersion::Tls12,
            TlsVersion::Tls13,
        ];
        config.min_protocol_version = TlsVersion::Tls10;
        config
    }

    pub fn danger_accept_invalid_certs(mut self) -> Self {
        self.accept_invalid_certs = true;
        self
    }

    pub fn danger_accept_invalid_hostnames(mut self) -> Self {
        self.accept_invalid_hostnames = true;
        self
    }

    pub fn with_ca_certs(mut self, ca_certs: Vec<Vec<u8>>) -> Self {
        self.ca_certs = ca_certs;
        self
    }

    pub fn with_client_cert(mut self, client_cert: ClientCertificate) -> Self {
        self.client_cert = Some(client_cert);
        self
    }

    pub fn with_supported_versions(mut self, versions: Vec<TlsVersion>) -> Self {
        self.supported_versions = versions;
        self
    }
    
    pub fn with_min_protocol_version(mut self, version: TlsVersion) -> Self {
        self.min_protocol_version = version;
        self
    }
    
    pub fn with_max_protocol_version(mut self, version: TlsVersion) -> Self {
        self.max_protocol_version = version;
        self
    }
    
    pub fn with_cipher_suites(mut self, cipher_suites: Vec<u16>) -> Self {
        self.cipher_suites = cipher_suites;
        self
    }
    
    pub fn with_alpn_protocols(mut self, protocols: Vec<String>) -> Self {
        self.alpn_protocols = protocols;
        self
    }
    
    pub fn disable_sni(mut self) -> Self {
        self.enable_sni = false;
        self
    }
    
    pub fn disable_alpn(mut self) -> Self {
        self.enable_alpn = false;
        self
    }
    
    pub fn with_session_cache_size(mut self, size: usize) -> Self {
        self.session_cache_size = size;
        self
    }
    
    pub fn with_session_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.session_timeout = timeout;
        self
    }
    
    pub fn enable_ocsp_stapling(mut self) -> Self {
        self.enable_ocsp_stapling = true;
        self
    }
    
    pub fn disable_sct(mut self) -> Self {
        self.enable_sct = false;
        self
    }
    
    /// Check if configuration is secure
    pub fn is_secure(&self) -> bool {
        self.min_protocol_version >= TlsVersion::Tls12 && 
        self.verify_certificates && 
        !self.accept_invalid_certs
    }
    
    /// Get supported cipher suites as objects
    pub fn get_cipher_suites(&self) -> Vec<CipherSuite> {
        self.cipher_suites
            .iter()
            .filter_map(|&id| get_cipher_suite_info(id))
            .collect()
    }
    
    /// Filter cipher suites by security level
    pub fn filter_by_security_level(&self, min_level: SecurityLevel) -> Vec<u16> {
        self.cipher_suites
            .iter()
            .filter(|&&id| {
                if let Some(suite) = get_cipher_suite_info(id) {
                    suite.security_level >= min_level
                } else {
                    false
                }
            })
            .copied()
            .collect()
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct ClientCertificate {
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
    pub password: Option<String>,
    pub cert_format: CertificateFormat,
    pub key_format: KeyFormat,
}

impl ClientCertificate {
    pub fn new(cert: Vec<u8>, key: Vec<u8>) -> Self {
        ClientCertificate {
            cert,
            key,
            password: None,
            cert_format: CertificateFormat::PEM,
            key_format: KeyFormat::PEM,
        }
    }
    
    pub fn from_pem(cert_pem: Vec<u8>, key_pem: Vec<u8>) -> Self {
        ClientCertificate {
            cert: cert_pem,
            key: key_pem,
            password: None,
            cert_format: CertificateFormat::PEM,
            key_format: KeyFormat::PEM,
        }
    }
    
    pub fn from_der(cert_der: Vec<u8>, key_der: Vec<u8>) -> Self {
        ClientCertificate {
            cert: cert_der,
            key: key_der,
            password: None,
            cert_format: CertificateFormat::DER,
            key_format: KeyFormat::DER,
        }
    }
    
    pub fn from_pkcs12(pkcs12_data: Vec<u8>, password: String) -> Self {
        ClientCertificate {
            cert: pkcs12_data.clone(),
            key: pkcs12_data,
            password: Some(password),
            cert_format: CertificateFormat::PKCS12,
            key_format: KeyFormat::PKCS8,
        }
    }

    pub fn with_password(mut self, password: String) -> Self {
        self.password = Some(password);
        self
    }
    
    pub fn with_cert_format(mut self, format: CertificateFormat) -> Self {
        self.cert_format = format;
        self
    }
    
    pub fn with_key_format(mut self, format: KeyFormat) -> Self {
        self.key_format = format;
        self
    }
    
    /// Validate certificate and key
    pub fn validate(&self) -> Result<()> {
        if self.cert.is_empty() {
            return Err(Error::TlsError("Certificate is empty".to_string()));
        }
        
        if self.key.is_empty() {
            return Err(Error::TlsError("Private key is empty".to_string()));
        }
        
        // Check if PKCS12 format requires password
        if self.cert_format == CertificateFormat::PKCS12 && self.password.is_none() {
            return Err(Error::TlsError("PKCS12 format requires password".to_string()));
        }
        
        Ok(())
    }
    
    /// Get certificate information
    pub fn get_info(&self) -> CertificateInfo {
        CertificateInfo {
            format: self.cert_format,
            cert_size: self.cert.len(),
            key_format: self.key_format,
            key_size: self.key.len(),
            has_password: self.password.is_some(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub format: CertificateFormat,
    pub cert_size: usize,
    pub key_format: KeyFormat,
    pub key_size: usize,
    pub has_password: bool,
}

// TLS stream implementation
pub struct TlsStream {
    inner: TcpStream,
}

impl TlsStream {
    pub fn connect(stream: TcpStream, _hostname: &str, _config: &TlsConfig) -> Result<Self> {
        // In a real implementation, this would perform the full TLS handshake
        // For now, we just wrap the stream
        Ok(TlsStream { inner: stream })
    }

    pub fn into_inner(self) -> TcpStream {
        self.inner
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Get cipher suite information by ID
pub fn get_cipher_suite_info(id: u16) -> Option<CipherSuite> {
    match id {
        0x1301 => Some(CipherSuite {
            id,
            name: "TLS_AES_128_GCM_SHA256".to_string(),
            key_exchange: KeyExchangeAlgorithm::ECDHE,
            authentication: AuthenticationAlgorithm::RSA,
            encryption: EncryptionAlgorithm::AES128GCM,
            mac: MacAlgorithm::AEAD,
            security_level: SecurityLevel::Strong,
        }),
        0x1302 => Some(CipherSuite {
            id,
            name: "TLS_AES_256_GCM_SHA384".to_string(),
            key_exchange: KeyExchangeAlgorithm::ECDHE,
            authentication: AuthenticationAlgorithm::RSA,
            encryption: EncryptionAlgorithm::AES256GCM,
            mac: MacAlgorithm::AEAD,
            security_level: SecurityLevel::Strong,
        }),
        0x1303 => Some(CipherSuite {
            id,
            name: "TLS_CHACHA20_POLY1305_SHA256".to_string(),
            key_exchange: KeyExchangeAlgorithm::ECDHE,
            authentication: AuthenticationAlgorithm::RSA,
            encryption: EncryptionAlgorithm::ChaCha20Poly1305,
            mac: MacAlgorithm::AEAD,
            security_level: SecurityLevel::Strong,
        }),
        0xc02f => Some(CipherSuite {
            id,
            name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
            key_exchange: KeyExchangeAlgorithm::ECDHE,
            authentication: AuthenticationAlgorithm::RSA,
            encryption: EncryptionAlgorithm::AES128GCM,
            mac: MacAlgorithm::AEAD,
            security_level: SecurityLevel::Strong,
        }),
        0xc030 => Some(CipherSuite {
            id,
            name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
            key_exchange: KeyExchangeAlgorithm::ECDHE,
            authentication: AuthenticationAlgorithm::RSA,
            encryption: EncryptionAlgorithm::AES256GCM,
            mac: MacAlgorithm::AEAD,
            security_level: SecurityLevel::Strong,
        }),
        0xcca9 => Some(CipherSuite {
            id,
            name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
            key_exchange: KeyExchangeAlgorithm::ECDHE,
            authentication: AuthenticationAlgorithm::ECDSA,
            encryption: EncryptionAlgorithm::ChaCha20Poly1305,
            mac: MacAlgorithm::AEAD,
            security_level: SecurityLevel::Strong,
        }),
        _ => None,
    }
}

/// Get all available cipher suites
pub fn get_all_cipher_suites() -> Vec<CipherSuite> {
    vec![
        0x1301, 0x1302, 0x1303, 0xc02f, 0xc030, 0xcca9,
    ]
    .into_iter()
    .filter_map(get_cipher_suite_info)
    .collect()
}

/// Get cipher suites by minimum security level
pub fn get_cipher_suites_by_security_level(min_level: SecurityLevel) -> Vec<CipherSuite> {
    get_all_cipher_suites()
        .into_iter()
        .filter(|suite| suite.security_level >= min_level)
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_version() {
        assert_eq!(TlsVersion::Tls12.as_u16(), 0x0303);
        assert_eq!(TlsVersion::Tls13.as_u16(), 0x0304);
        
        assert_eq!(TlsVersion::from_u16(0x0303), Some(TlsVersion::Tls12));
        assert_eq!(TlsVersion::from_u16(0x0304), Some(TlsVersion::Tls13));
        assert_eq!(TlsVersion::from_u16(0x9999), None);
        
        assert_eq!(TlsVersion::Tls12.as_str(), "TLSv1.2");
        assert_eq!(TlsVersion::Tls13.as_str(), "TLSv1.3");
        
        assert!(!TlsVersion::Tls10.is_secure());
        assert!(!TlsVersion::Tls11.is_secure());
        assert!(TlsVersion::Tls12.is_secure());
        assert!(TlsVersion::Tls13.is_secure());
        
        assert_eq!(TlsVersion::Tls13.as_bytes(), [0x03, 0x04]);
    }

    #[test]
    fn test_tls_config_creation() {
        let config = TlsConfig::new();
        assert!(config.verify_certificates);
        assert!(!config.accept_invalid_hostnames);
        assert!(!config.accept_invalid_certs);
        assert!(config.enable_sni);
        assert!(config.enable_alpn);
        assert_eq!(config.min_protocol_version, TlsVersion::Tls12);
        assert_eq!(config.max_protocol_version, TlsVersion::Tls13);
    }

    #[test]
    fn test_tls_config_secure() {
        let config = TlsConfig::secure();
        assert!(config.is_secure());
        assert_eq!(config.min_protocol_version, TlsVersion::Tls12);
        assert!(config.cipher_suites.contains(&0x1301)); // TLS_AES_128_GCM_SHA256
    }

    #[test]
    fn test_tls_config_compatible() {
        let config = TlsConfig::compatible();
        assert_eq!(config.min_protocol_version, TlsVersion::Tls10);
        assert!(config.supported_versions.contains(&TlsVersion::Tls10));
        assert!(config.supported_versions.contains(&TlsVersion::Tls13));
    }

    #[test]
    fn test_tls_config_builder() {
        let config = TlsConfig::new()
            .danger_accept_invalid_certs()
            .danger_accept_invalid_hostnames()
            .with_min_protocol_version(TlsVersion::Tls11)
            .with_alpn_protocols(vec!["h2".to_string()])
            .disable_sni()
            .with_session_cache_size(500);

        assert!(config.accept_invalid_certs);
        assert!(config.accept_invalid_hostnames);
        assert_eq!(config.min_protocol_version, TlsVersion::Tls11);
        assert_eq!(config.alpn_protocols, vec!["h2"]);
        assert!(!config.enable_sni);
        assert_eq!(config.session_cache_size, 500);
    }

    #[test]
    fn test_client_certificate() {
        let cert_data = b"test_cert_data".to_vec();
        let key_data = b"test_key_data".to_vec();
        
        let client_cert = ClientCertificate::new(cert_data.clone(), key_data.clone())
            .with_password("test_password".to_string());

        assert_eq!(client_cert.cert, cert_data);
        assert_eq!(client_cert.key, key_data);
        assert_eq!(client_cert.password, Some("test_password".to_string()));
        assert_eq!(client_cert.cert_format, CertificateFormat::PEM);
        assert_eq!(client_cert.key_format, KeyFormat::PEM);
        
        assert!(client_cert.validate().is_ok());
        
        let info = client_cert.get_info();
        assert_eq!(info.format, CertificateFormat::PEM);
        assert!(info.has_password);
        assert_eq!(info.cert_size, cert_data.len());
        assert_eq!(info.key_size, key_data.len());
    }

    #[test]
    fn test_client_certificate_pkcs12() {
        let pkcs12_data = b"pkcs12_test_data".to_vec();
        let client_cert = ClientCertificate::from_pkcs12(pkcs12_data, "password".to_string());

        assert_eq!(client_cert.cert_format, CertificateFormat::PKCS12);
        assert_eq!(client_cert.password, Some("password".to_string()));
        assert!(client_cert.validate().is_ok());
    }

    #[test]
    fn test_client_certificate_validation() {
        let empty_cert = ClientCertificate::new(vec![], b"test".to_vec());
        assert!(empty_cert.validate().is_err());
        
        let empty_key = ClientCertificate::new(b"test".to_vec(), vec![]);
        assert!(empty_key.validate().is_err());
        
        let pkcs12_no_password = ClientCertificate {
            cert: b"test".to_vec(),
            key: b"test".to_vec(),
            password: None,
            cert_format: CertificateFormat::PKCS12,
            key_format: KeyFormat::PKCS8,
        };
        assert!(pkcs12_no_password.validate().is_err());
    }

    #[test]
    fn test_cipher_suite_info() {
        let suite = get_cipher_suite_info(0x1301).unwrap();
        assert_eq!(suite.id, 0x1301);
        assert_eq!(suite.name, "TLS_AES_128_GCM_SHA256");
        assert_eq!(suite.key_exchange, KeyExchangeAlgorithm::ECDHE);
        assert_eq!(suite.authentication, AuthenticationAlgorithm::RSA);
        assert_eq!(suite.encryption, EncryptionAlgorithm::AES128GCM);
        assert_eq!(suite.mac, MacAlgorithm::AEAD);
        assert_eq!(suite.security_level, SecurityLevel::Strong);
        
        assert!(get_cipher_suite_info(0x9999).is_none());
    }

    #[test]
    fn test_get_all_cipher_suites() {
        let suites = get_all_cipher_suites();
        assert!(!suites.is_empty());
        assert!(suites.iter().any(|s| s.id == 0x1301));
        assert!(suites.iter().any(|s| s.id == 0x1302));
    }

    #[test]
    fn test_cipher_suites_by_security_level() {
        let strong_suites = get_cipher_suites_by_security_level(SecurityLevel::Strong);
        assert!(!strong_suites.is_empty());
        assert!(strong_suites.iter().all(|s| s.security_level >= SecurityLevel::Strong));
        
        let very_strong_suites = get_cipher_suites_by_security_level(SecurityLevel::VeryStrong);
        assert!(very_strong_suites.is_empty()); // No VeryStrong suites in our test set
    }

    #[test]
    fn test_tls_config_cipher_suite_filtering() {
        let config = TlsConfig::new();
        let cipher_suites = config.get_cipher_suites();
        assert!(!cipher_suites.is_empty());
        
        let strong_ciphers = config.filter_by_security_level(SecurityLevel::Strong);
        assert!(!strong_ciphers.is_empty());
        
        let very_strong_ciphers = config.filter_by_security_level(SecurityLevel::VeryStrong);
        assert!(very_strong_ciphers.is_empty());
    }

    #[test]
    fn test_security_level_ordering() {
        assert!(SecurityLevel::VeryStrong > SecurityLevel::Strong);
        assert!(SecurityLevel::Strong > SecurityLevel::Medium);
        assert!(SecurityLevel::Medium > SecurityLevel::Weak);
    }

    #[test]
    fn test_tls_config_security_check() {
        let secure_config = TlsConfig::secure();
        assert!(secure_config.is_secure());
        
        let insecure_config = TlsConfig::new()
            .danger_accept_invalid_certs();
        assert!(!insecure_config.is_secure());
        
        let old_tls_config = TlsConfig::new()
            .with_min_protocol_version(TlsVersion::Tls10);
        assert!(!old_tls_config.is_secure());
    }

    #[test]
    fn test_certificate_formats() {
        assert_ne!(CertificateFormat::PEM, CertificateFormat::DER);
        assert_ne!(CertificateFormat::PEM, CertificateFormat::PKCS12);
        
        assert_ne!(KeyFormat::PEM, KeyFormat::DER);
        assert_ne!(KeyFormat::PKCS8, KeyFormat::PKCS1RSA);
    }

    #[test]
    fn test_tls_version_ordering() {
        assert!(TlsVersion::Tls13 > TlsVersion::Tls12);
        assert!(TlsVersion::Tls12 > TlsVersion::Tls11);
        assert!(TlsVersion::Tls11 > TlsVersion::Tls10);
    }

    #[test]
    fn test_default_config() {
        let config1 = TlsConfig::default();
        let config2 = TlsConfig::new();
        
        assert_eq!(config1.verify_certificates, config2.verify_certificates);
        assert_eq!(config1.min_protocol_version, config2.min_protocol_version);
        assert_eq!(config1.cipher_suites, config2.cipher_suites);
    }

    #[test]
    fn test_certificate_info() {
        let cert = ClientCertificate::from_pem(b"cert".to_vec(), b"key".to_vec());
        let info = cert.get_info();
        
        assert_eq!(info.format, CertificateFormat::PEM);
        assert_eq!(info.key_format, KeyFormat::PEM);
        assert_eq!(info.cert_size, 4);
        assert_eq!(info.key_size, 3);
        assert!(!info.has_password);
    }

    #[test]
    fn test_tls_config_session_settings() {
        let timeout = std::time::Duration::from_secs(7200);
        let config = TlsConfig::new()
            .with_session_cache_size(2000)
            .with_session_timeout(timeout);
        
        assert_eq!(config.session_cache_size, 2000);
        assert_eq!(config.session_timeout, timeout);
    }

    #[test]
    fn test_tls_config_ocsp_and_sct() {
        let config = TlsConfig::new()
            .enable_ocsp_stapling()
            .disable_sct();
        
        assert!(config.enable_ocsp_stapling);
        assert!(!config.enable_sct);
    }
}