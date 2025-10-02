# Salted Challenge Response Authentication Mechanism (SCRAM)

This implementation provides a client and a server for the SCRAM-SHA-256 mechanism according to
RFC5802 and RFC7677. The server implementation supports channel-binding for enhanced security
over TLS connections.

[Read the documentation.](https://docs.rs/scram)

# Limitations

The mandatory SCRAM-SHA-1 authentication mechanism is currently not implemented. The client does not
yet support channel-binding (only the server supports it). If you like to contribute or maintain
these features I appreciate that.

# Usage

## Client

A typical usage scenario is shown below. For a detailed explanation of the methods please
consider their documentation. In productive code you should replace the unwrapping by proper
error handling.

At first the user and the password must be supplied using either of the methods
`ClientFirst::new` or `ClientFirst::with_rng`. These methods return a SCRAM
state you can use to compute the first client message.

The server and the client exchange four messages using the SCRAM mechanism. There is a rust type
for each one of them. Calling the methods `client_first`, `handle_server_first`, `client_final`
and `handle_server_final` on the different types advances the SCRAM handshake step by step.
Computing client messages never fails but processing server messages can result in failure.

```rust
use scram::ScramClient;

// This function represents your I/O implementation.
fn send_and_receive(message: &str) -> String {
    unimplemented!()
}

// Create a SCRAM state from the credentials.
let scram = ScramClient::new("user", "password", None);

// Get the client message and reassign the SCRAM state.
let (scram, client_first) = scram.client_first();

// Send the client first message and receive the servers reply.
let server_first = send_and_receive(&client_first);

// Process the reply and again reassign the SCRAM state. You can add error handling to
// abort the authentication attempt.
let scram = scram.handle_server_first(&server_first).unwrap();

// Get the client final message and reassign the SCRAM state.
let (scram, client_final) = scram.client_final();

// Send the client final message and receive the servers reply.
let server_final = send_and_receive(&client_final);

// Process the last message. Any error returned means that the authentication attempt
// wasn't successful.
let () = scram.handle_server_final(&server_final).unwrap();
```

## Server

The server is created to respond to incoming challenges from a client.  A typical usage pattern,
with a default provider is shown below.  In production, you would implement an AuthenticationProvider
that could look up user credentials based on a username

The server and the client exchange four messages using the SCRAM mechanism. There is a rust type for
each one of them. Calling the methods `handle_client_first()`, `server_first()`,
`handle_client_final()` and `server_final()` on the different types advances the SCRAM handshake
step by step. Computing server messages never fails (unless the source of randomness for the nonce
fails), but processing client messages can result in failure.

The final step will not return an error if authentication failed, but will return an
`AuthenticationStatus` which you can use to determine if authentication was successful or not.

```rust
use scram::{ScramServer, AuthenticationStatus, AuthenticationProvider, PasswordInfo};

// Create a dummy authentication provider
struct ExampleProvider;
impl AuthenticationProvider for ExampleProvider {
    // Here you would look up password information for the the given username
    fn get_password_for(&self, username: &str) -> Option<PasswordInfo> {
       unimplemented!()
    }

}
// These functions represent your I/O implementation.
# #[allow(unused_variables)]
fn receive() -> String {
    unimplemented!()
}
# #[allow(unused_variables)]
fn send(message: &str) {
    unimplemented!()
}

// Create a new ScramServer using the example authenication provider
let scram_server = ScramServer::new(ExampleProvider{});

// Receive a message from the client
let client_first = receive();

// Create a SCRAM state from the client's first message
let scram_server = scram_server.handle_client_first(&client_first).unwrap();
// Craft a response to the client's message and advance the SCRAM state
// We could use our own source of randomness here, with `server_first_with_rng()`
let (scram_server, server_first) = scram_server.server_first();
// Send our message to the client and read the response
send(&server_first);
let client_final = receive();

// Process the client's challenge and re-assign the SCRAM state.  This could fail if the
// message was poorly formatted
let scram_server = scram_server.handle_client_final(&client_final).unwrap();

// Prepare the final message and get the authentication status
let(status, server_final) = scram_server.server_final();
// Send our final message to the client
send(&server_final);

// Check if the client successfully authenticated
assert_eq!(status, AuthenticationStatus::Authenticated);
```

## Channel Binding

The server implementation supports channel binding, which cryptographically binds the SCRAM
authentication to the underlying TLS connection. This prevents man-in-the-middle attacks even if
the attacker has a valid TLS certificate.

To use channel binding, obtain the channel binding data from your TLS implementation and create
the server with `ScramServer::new_with_channel_binding`:

```rust
use scram::{ScramServer, AuthenticationProvider, PasswordInfo};

struct ExampleProvider;
impl AuthenticationProvider for ExampleProvider {
    fn get_password_for(&self, username: &str) -> Option<PasswordInfo> {
       unimplemented!()
    }
}

// Get channel binding data from your TLS implementation
let cb_type = "tls-unique".to_string();
let cb_data = get_tls_channel_binding_data(); // From your TLS library

// Create server with channel binding
let scram_server = ScramServer::new_with_channel_binding(
    ExampleProvider{},
    cb_type,
    cb_data
);
```

Common channel binding types:
- `tls-unique`: Uses the TLS Finished message (most common)
- `tls-server-end-point`: Uses a hash of the server's TLS certificate
- `tls-exporter`: Uses the TLS exporter functionality (RFC 5705)

When channel binding is configured, the server will:
1. Accept only clients that use the same channel binding type
2. Validate that the channel binding data from the client matches the server's TLS connection
3. Reject clients that don't support channel binding (for security)
```
