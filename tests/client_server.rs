extern crate aws_lc_rs;
extern crate base64;
extern crate rand;
extern crate scram;

use aws_lc_rs::digest::SHA256_OUTPUT_LEN;
use scram::*;
use std::num::NonZeroU32;

struct TestProvider {
    user_password: [u8; SHA256_OUTPUT_LEN],
    admin_password: [u8; SHA256_OUTPUT_LEN],
}

impl TestProvider {
    pub fn new() -> Self {
        let pwd_iterations = NonZeroU32::new(4096).unwrap();
        let user_password = hash_password("password", pwd_iterations, b"salt");
        let adm_iterations = NonZeroU32::new(8192).unwrap();
        let admin_password = hash_password("admin_password", adm_iterations, b"messy");
        TestProvider {
            user_password: user_password,
            admin_password: admin_password,
        }
    }
}

impl server::AuthenticationProvider for TestProvider {
    fn get_password_for(&self, username: &str) -> Option<server::PasswordInfo> {
        match username {
            "user" => Some(server::PasswordInfo::new(
                self.user_password.to_vec(),
                4096,
                "salt".bytes().collect(),
            )),
            "admin" => Some(server::PasswordInfo::new(
                self.admin_password.to_vec(),
                8192,
                "messy".bytes().collect(),
            )),
            _ => None,
        }
    }

    fn authorize(&self, authcid: &str, authzid: &str) -> bool {
        authcid == authzid || authcid == "admin" && authzid == "user"
    }
}

struct MultiPasswordProvider {
    hashes: Vec<Vec<u8>>,
    salt: Vec<u8>,
    iterations: u16,
}

impl MultiPasswordProvider {
    fn new(passwords: &[&str], salt: &[u8], iterations: u16) -> Self {
        let iter_nz = NonZeroU32::new(iterations as u32).unwrap();
        let hashes = passwords
            .iter()
            .map(|p| hash_password(p, iter_nz, salt).to_vec())
            .collect();
        Self {
            hashes,
            salt: salt.to_vec(),
            iterations,
        }
    }
}

impl server::AuthenticationProvider for MultiPasswordProvider {
    fn get_password_for(&self, _username: &str) -> Option<server::PasswordInfo> {
        Some(server::PasswordInfo::new_multi(
            self.hashes.clone(),
            self.iterations,
            self.salt.clone(),
        ))
    }
}

fn run_handshake(client_password: &str, provider: MultiPasswordProvider) -> AuthenticationStatus {
    let scram_client = ScramClient::new("user", client_password, None);
    let scram_server = ScramServer::new(provider);

    let (scram_client, client_first) = scram_client.client_first();
    let scram_server = scram_server.handle_client_first(&client_first).unwrap();
    let (scram_server, server_first) = scram_server.server_first();
    let scram_client = scram_client.handle_server_first(&server_first).unwrap();
    let (scram_client, client_final) = scram_client.client_final();
    let scram_server = scram_server.handle_client_final(&client_final).unwrap();
    let (status, server_final) = scram_server.server_final();
    if status == AuthenticationStatus::Authenticated {
        scram_client.handle_server_final(&server_final).unwrap();
    }
    status
}

#[test]
fn test_multi_password_first_matches() {
    let provider = MultiPasswordProvider::new(&["alpha", "beta", "gamma"], b"salty", 4096);
    assert_eq!(
        run_handshake("alpha", provider),
        AuthenticationStatus::Authenticated
    );
}

#[test]
fn test_multi_password_middle_matches() {
    let provider = MultiPasswordProvider::new(&["alpha", "beta", "gamma"], b"salty", 4096);
    assert_eq!(
        run_handshake("beta", provider),
        AuthenticationStatus::Authenticated
    );
}

#[test]
fn test_multi_password_last_matches() {
    let provider = MultiPasswordProvider::new(&["alpha", "beta", "gamma"], b"salty", 4096);
    assert_eq!(
        run_handshake("gamma", provider),
        AuthenticationStatus::Authenticated
    );
}

#[test]
fn test_multi_password_none_match() {
    let provider = MultiPasswordProvider::new(&["alpha", "beta", "gamma"], b"salty", 4096);
    assert_eq!(
        run_handshake("delta", provider),
        AuthenticationStatus::NotAuthenticated
    );
}

#[test]
fn test_simple_success() {
    let scram_client = ScramClient::new("user", "password", None);
    let scram_server = ScramServer::new(TestProvider::new());

    let (scram_client, client_first) = scram_client.client_first();

    let scram_server = scram_server.handle_client_first(&client_first).unwrap();
    let (scram_server, server_first) = scram_server.server_first();

    let scram_client = scram_client.handle_server_first(&server_first).unwrap();
    let (scram_client, client_final) = scram_client.client_final();

    let scram_server = scram_server.handle_client_final(&client_final).unwrap();
    let (status, server_final) = scram_server.server_final();

    scram_client.handle_server_final(&server_final).unwrap();

    assert_eq!(status, AuthenticationStatus::Authenticated);
}

#[test]
fn test_bad_password() {
    let scram_client = ScramClient::new("user", "badpassword", None);
    let scram_server = ScramServer::new(TestProvider::new());

    let (scram_client, client_first) = scram_client.client_first();

    let scram_server = scram_server.handle_client_first(&client_first).unwrap();
    let (scram_server, server_first) = scram_server.server_first();

    let scram_client = scram_client.handle_server_first(&server_first).unwrap();
    let (scram_client, client_final) = scram_client.client_final();

    let scram_server = scram_server.handle_client_final(&client_final).unwrap();
    let (status, server_final) = scram_server.server_final();

    assert_eq!(status, AuthenticationStatus::NotAuthenticated);
    assert!(scram_client.handle_server_final(&server_final).is_err());
}

#[test]
fn test_authorize_different() {
    let scram_client = ScramClient::new("admin", "admin_password", Some("user"));
    let scram_server = ScramServer::new(TestProvider::new());

    let (scram_client, client_first) = scram_client.client_first();

    let scram_server = scram_server.handle_client_first(&client_first).unwrap();
    let (scram_server, server_first) = scram_server.server_first();

    let scram_client = scram_client.handle_server_first(&server_first).unwrap();
    let (scram_client, client_final) = scram_client.client_final();

    let scram_server = scram_server.handle_client_final(&client_final).unwrap();
    let (status, server_final) = scram_server.server_final();

    scram_client.handle_server_final(&server_final).unwrap();

    assert_eq!(status, AuthenticationStatus::Authenticated);
}

#[test]
fn test_authorize_fail() {
    let scram_client = ScramClient::new("user", "password", Some("admin"));
    let scram_server = ScramServer::new(TestProvider::new());

    let (scram_client, client_first) = scram_client.client_first();

    let scram_server = scram_server.handle_client_first(&client_first).unwrap();
    let (scram_server, server_first) = scram_server.server_first();

    let scram_client = scram_client.handle_server_first(&server_first).unwrap();
    let (scram_client, client_final) = scram_client.client_final();

    let scram_server = scram_server.handle_client_final(&client_final).unwrap();
    let (status, server_final) = scram_server.server_final();

    assert_eq!(status, AuthenticationStatus::NotAuthorized);
    assert!(scram_client.handle_server_final(&server_final).is_err());
}

#[test]
fn test_authorize_non_existent() {
    let scram_client = ScramClient::new("admin", "admin_password", Some("nonexistent"));
    let scram_server = ScramServer::new(TestProvider::new());

    let (scram_client, client_first) = scram_client.client_first();

    let scram_server = scram_server.handle_client_first(&client_first).unwrap();
    let (scram_server, server_first) = scram_server.server_first();

    let scram_client = scram_client.handle_server_first(&server_first).unwrap();
    let (scram_client, client_final) = scram_client.client_final();

    let scram_server = scram_server.handle_client_final(&client_final).unwrap();
    let (status, server_final) = scram_server.server_final();

    assert_eq!(status, AuthenticationStatus::NotAuthorized);
    assert!(scram_client.handle_server_final(&server_final).is_err());
}

#[test]
fn test_invalid_user() {
    let scram_client = ScramClient::new("nobody", "password", None);
    let scram_server = ScramServer::new(TestProvider::new());

    let (_, client_first) = scram_client.client_first();

    assert!(scram_server.handle_client_first(&client_first).is_err())
}

#[test]
fn test_empty_username() {
    let scram_client = ScramClient::new("", "password", None);
    let scram_server = ScramServer::new(TestProvider::new());

    let (_, client_first) = scram_client.client_first();

    assert!(scram_server.handle_client_first(&client_first).is_err())
}

#[test]
fn test_empty_password() {
    let scram_client = ScramClient::new("user", "", None);
    let scram_server = ScramServer::new(TestProvider::new());

    let (scram_client, client_first) = scram_client.client_first();

    let scram_server = scram_server.handle_client_first(&client_first).unwrap();
    let (scram_server, server_first) = scram_server.server_first();

    let scram_client = scram_client.handle_server_first(&server_first).unwrap();
    let (scram_client, client_final) = scram_client.client_final();

    let scram_server = scram_server.handle_client_final(&client_final).unwrap();
    let (status, server_final) = scram_server.server_final();

    assert_eq!(status, AuthenticationStatus::NotAuthenticated);
    assert!(scram_client.handle_server_final(&server_final).is_err());
}

fn plus_handshake(
    password: &str,
    cb_type: &str,
    client_cb: Vec<u8>,
    server_cb: Vec<u8>,
) -> AuthenticationStatus {
    let scram_client =
        ScramClient::new_with_channel_binding("user", password, None, cb_type, client_cb);
    let scram_server =
        ScramServer::new_with_channel_binding(TestProvider::new(), cb_type.to_string(), server_cb);

    let (scram_client, client_first) = scram_client.client_first();
    assert!(
        client_first.starts_with(&format!("p={},,", cb_type)),
        "PLUS client-first must use the p= GS2 flag"
    );

    let scram_server = scram_server.handle_client_first(&client_first).unwrap();
    let (scram_server, server_first) = scram_server.server_first();

    let scram_client = scram_client.handle_server_first(&server_first).unwrap();
    let (scram_client, client_final) = scram_client.client_final();

    let scram_server = scram_server.handle_client_final(&client_final).unwrap();
    let (status, server_final) = scram_server.server_final();

    if status == AuthenticationStatus::Authenticated {
        scram_client.handle_server_final(&server_final).unwrap();
    }
    status
}

#[test]
fn test_channel_binding_success() {
    let cb_data = b"channel-binding-data-from-tls".to_vec();
    assert_eq!(
        plus_handshake("password", "tls-server-end-point", cb_data.clone(), cb_data),
        AuthenticationStatus::Authenticated
    );
}

#[test]
fn test_channel_binding_wrong_data() {
    let client_cb = b"channel-binding-data-from-tls".to_vec();
    let server_cb = b"different-binding-data".to_vec();
    let scram_client = ScramClient::new_with_channel_binding(
        "user",
        "password",
        None,
        "tls-server-end-point",
        client_cb,
    );
    let scram_server = ScramServer::new_with_channel_binding(
        TestProvider::new(),
        "tls-server-end-point".to_string(),
        server_cb,
    );

    let (scram_client, client_first) = scram_client.client_first();
    let scram_server = scram_server.handle_client_first(&client_first).unwrap();
    let (scram_server, server_first) = scram_server.server_first();
    let scram_client = scram_client.handle_server_first(&server_first).unwrap();
    let (_scram_client, client_final) = scram_client.client_final();

    assert!(
        scram_server.handle_client_final(&client_final).is_err(),
        "mismatched channel-binding data must fail the handshake"
    );
}

#[test]
fn test_channel_binding_wrong_password() {
    let cb_data = b"channel-binding-data-from-tls".to_vec();
    assert_eq!(
        plus_handshake(
            "badpassword",
            "tls-server-end-point",
            cb_data.clone(),
            cb_data
        ),
        AuthenticationStatus::NotAuthenticated
    );
}

#[test]
fn test_channel_binding_y_flag_rejected() {
    let cb_data = b"channel-binding-data".to_vec();
    let scram_server = ScramServer::new_with_channel_binding(
        TestProvider::new(),
        "tls-server-end-point".to_string(),
        cb_data,
    );

    // RFC 5802: client sent `y` but the server does support channel binding.
    let client_first = "y,,n=user,r=clientnonce";
    assert!(scram_server.handle_client_first(client_first).is_err());
}

#[test]
fn test_channel_binding_type_mismatch() {
    let cb_data = b"channel-binding-data".to_vec();

    // Server expects tls-unique
    let scram_server = ScramServer::new_with_channel_binding(
        TestProvider::new(),
        "tls-unique".to_string(),
        cb_data,
    );

    // Client sends tls-server-end-point
    let client_first = "p=tls-server-end-point,,n=user,r=clientnonce";

    // Should fail due to channel binding type mismatch
    assert!(scram_server.handle_client_first(client_first).is_err());
}

#[test]
fn test_channel_binding_client_not_supporting() {
    let cb_data = b"channel-binding-data".to_vec();

    // Server expects channel binding
    let scram_server = ScramServer::new_with_channel_binding(
        TestProvider::new(),
        "tls-unique".to_string(),
        cb_data,
    );

    // Client doesn't support channel binding (sends "n")
    let client_first = "n,,n=user,r=clientnonce";

    // Should fail because server requires channel binding but client doesn't support it
    assert!(scram_server.handle_client_first(client_first).is_err());
}

#[test]
fn test_channel_binding_server_not_supporting() {
    // Server doesn't support channel binding
    let scram_server = ScramServer::new(TestProvider::new());

    // Client wants to use channel binding
    let client_first = "p=tls-unique,,n=user,r=clientnonce";

    // Should fail because client wants channel binding but server doesn't support it
    assert!(scram_server.handle_client_first(client_first).is_err());
}

/// Provider that returns stored keys parsed from a pg_shadow-style SCRAM hash.
struct StoredKeyProvider {
    stored_key: Vec<u8>,
    server_key: Vec<u8>,
    salt: Vec<u8>,
    iterations: u16,
}

impl StoredKeyProvider {
    /// Parse a `SCRAM-SHA-256$iter:salt$StoredKey:ServerKey` string.
    fn from_scram_hash(hash: &str) -> Self {
        let mut parts = hash.split('$');
        assert_eq!(parts.next().unwrap(), "SCRAM-SHA-256");
        let iter_salt = parts.next().unwrap();
        let keys = parts.next().unwrap();

        let mut is = iter_salt.split(':');
        let iterations: u16 = is.next().unwrap().parse().unwrap();
        let salt = base64::decode(is.next().unwrap()).unwrap();

        let mut ks = keys.split(':');
        let stored_key = base64::decode(ks.next().unwrap()).unwrap();
        let server_key = base64::decode(ks.next().unwrap()).unwrap();

        Self {
            stored_key,
            server_key,
            salt,
            iterations,
        }
    }
}

impl server::AuthenticationProvider for StoredKeyProvider {
    fn get_password_for(&self, _username: &str) -> Option<server::PasswordInfo> {
        Some(server::PasswordInfo::from_stored_keys(
            self.stored_key.clone(),
            self.server_key.clone(),
            self.iterations,
            self.salt.clone(),
        ))
    }
}

#[test]
fn test_stored_keys_correct_password() {
    let provider = StoredKeyProvider::from_scram_hash(
        "SCRAM-SHA-256$4096:B6lJyg12n6SawAu1kD9maA==$huWaU6t+WsvcS9ZrDvocZeYtlLJ60hdP46tjszFBbW0=:706OTwYyqH5WpfNpZdgt0gxuP5ff4DPUpHYu3F3w6TY=",
    );
    let scram_client = ScramClient::new("user", "pgdog", None);
    let scram_server = ScramServer::new(provider);

    let (scram_client, client_first) = scram_client.client_first();
    let scram_server = scram_server.handle_client_first(&client_first).unwrap();
    let (scram_server, server_first) = scram_server.server_first();
    let scram_client = scram_client.handle_server_first(&server_first).unwrap();
    let (scram_client, client_final) = scram_client.client_final();
    let scram_server = scram_server.handle_client_final(&client_final).unwrap();
    let (status, server_final) = scram_server.server_final();

    assert_eq!(status, AuthenticationStatus::Authenticated);
    scram_client.handle_server_final(&server_final).unwrap();
}

#[test]
fn test_stored_keys_wrong_password() {
    let provider = StoredKeyProvider::from_scram_hash(
        "SCRAM-SHA-256$4096:B6lJyg12n6SawAu1kD9maA==$huWaU6t+WsvcS9ZrDvocZeYtlLJ60hdP46tjszFBbW0=:706OTwYyqH5WpfNpZdgt0gxuP5ff4DPUpHYu3F3w6TY=",
    );
    let scram_client = ScramClient::new("user", "wrongpassword", None);
    let scram_server = ScramServer::new(provider);

    let (scram_client, client_first) = scram_client.client_first();
    let scram_server = scram_server.handle_client_first(&client_first).unwrap();
    let (scram_server, server_first) = scram_server.server_first();
    let scram_client = scram_client.handle_server_first(&server_first).unwrap();
    let (scram_client, client_final) = scram_client.client_final();
    let scram_server = scram_server.handle_client_final(&client_final).unwrap();
    let (status, server_final) = scram_server.server_final();

    assert_eq!(status, AuthenticationStatus::NotAuthenticated);
    assert!(scram_client.handle_server_final(&server_final).is_err());
}

#[test]
fn test_stored_keys_with_channel_binding() {
    let provider = StoredKeyProvider::from_scram_hash(
        "SCRAM-SHA-256$4096:B6lJyg12n6SawAu1kD9maA==$huWaU6t+WsvcS9ZrDvocZeYtlLJ60hdP46tjszFBbW0=:706OTwYyqH5WpfNpZdgt0gxuP5ff4DPUpHYu3F3w6TY=",
    );
    let cb_data = b"tls-server-end-point-bytes".to_vec();
    let scram_client = ScramClient::new_with_channel_binding(
        "user",
        "pgdog",
        None,
        "tls-server-end-point",
        cb_data.clone(),
    );
    let scram_server = ScramServer::new_with_channel_binding(
        provider,
        "tls-server-end-point".to_string(),
        cb_data,
    );

    let (scram_client, client_first) = scram_client.client_first();
    let scram_server = scram_server.handle_client_first(&client_first).unwrap();
    let (scram_server, server_first) = scram_server.server_first();
    let scram_client = scram_client.handle_server_first(&server_first).unwrap();
    let (scram_client, client_final) = scram_client.client_final();
    let scram_server = scram_server.handle_client_final(&client_final).unwrap();
    let (status, server_final) = scram_server.server_final();

    assert_eq!(status, AuthenticationStatus::Authenticated);
    scram_client.handle_server_final(&server_final).unwrap();
}
