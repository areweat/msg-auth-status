# msg-auth-status

[![Discord chat][discord-badge]][discord-url]
[![Crates.io](https://img.shields.io/crates/v/msg-auth-status.svg)](https://crates.io/crates/msg-auth-status)
[![Docs](https://docs.rs/msg-auth-status/badge.svg)](https://docs.rs/msg-auth-status)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![MSRV](https://img.shields.io/badge/MSRV-1.70.0-blue)

Parser & Verifier for Message-Authenticated-Status and the associated DKIM-Signatures.

## Add without Verifier

```ignore
cargo add msg-auth-status
```

## Add with Verifier

```ignore
cargo add msg-auth-status --features verifier
```

## RFCs

| RFC    | Tick | Description
| :---   | :--- | :--- |
| [8601] | ✅ Parsing | Message Header Field for Indicating Message Authentication Status |
| [6376] | ✅ Parsing | Domainkeys Identified Mail (DKIM) Signatures                      |

## Benches

On 10700K test_data/from_gmail_to_arewe_at.eml as of 2024 June 10

| Public API                                                   | Timings                         |
| :---                                                         | :---                            |
| `alloc_yes::MesssageAuthStatus::from_mail_parser`            | [685.76 ns 692.93 ns 705.28 ns] |
| `alloc_yes::DkimSignatures::from_mail_parser`                | [423.19 ns 424.95 ns 427.80 ns] |
| `From<mail_parser::HeaderValue>` for `DkimSignature`         | [301.46 ns 302.05 ns 302.69 ns] | 
| `From<mail_parser::HeaderValue>` for `AuthenticationResults` | [565.54 ns 567.40 ns 569.52 ns] |
| `ReturnPathVerifier::from_alloc_yes()` over Parsed           | [85.396 ns 85.579 ns 85.787 ns] |

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
