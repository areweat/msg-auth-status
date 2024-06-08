# msg-auth-status

[![Discord chat][discord-badge]][discord-url]
[![Crates.io](https://img.shields.io/crates/v/msg-auth-status.svg)](https://crates.io/crates/msg-auth-status)
[![Docs](https://docs.rs/msg-auth-status/badge.svg)](https://docs.rs/msg-auth-status)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![MSRV](https://img.shields.io/badge/MSRV-1.70.0-blue)

Parser and Verifier (opt-in) for Message-Authenticated-Status and the associated DKIM-Signatures.

## Add

```ignore
cargo add msg-auth-status --features verifier
```

## RFCs

| RFC    | Tick | Description
| :---   | :--- | :--- |
| [8601] | ✅ Parsing, Verifying*  | Message Header Field for Indicating Message Authentication Status |
| [6376] | ✅ Parsing, Verifying*  | Domainkeys Identified Mail (DKIM) Signatures                      |

* Note: This library does not facilitate any DNS lookups, DomainKeys public key must be supplied separately.

## See Also

- https://www.iana.org/assignments/dkim-parameters/dkim-parameters.xhtml
- https://www.iana.org/assignments/email-auth/email-auth.xhtml

[8601]: https://datatracker.ietf.org/doc/html/rfc8601
[6376]: https://datatracker.ietf.org/doc/html/rfc6376

## License

Licensed under either of:

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[discord-badge]: https://img.shields.io/discord/934761553952141402.svg?logo=discord
[discord-url]: https://discord.gg/rXVsmzhaZa
