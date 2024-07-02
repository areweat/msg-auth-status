use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::fs::File;
use std::io::Read;

fn load_test_data(file_location: &str) -> Vec<u8> {
    let mut file = File::open(file_location).unwrap();
    let mut data: Vec<u8> = vec![];
    file.read_to_end(&mut data).unwrap();
    data
}

use msg_auth_status::alloc_yes::DkimSignatures;
use msg_auth_status::alloc_yes::MessageAuthStatus;

#[cfg(feature = "verifier")]
use msg_auth_status::alloc_yes::ReturnPathVerifier;

use mail_parser::HeaderValue;
use msg_auth_status::alloc_yes::AuthenticationResults;
use msg_auth_status::dkim::DkimSignature;

fn criterion_benchmark(c: &mut Criterion) {
    let mail_data = load_test_data("test_data/from_gmail_to_arewe_at.eml");
    let parser = mail_parser::MessageParser::default();
    let parsed_message = parser.parse(&mail_data).unwrap();

    c.bench_function("alloc_yes::MesssageAuthStatus from_mail_parser", |b| {
        b.iter(|| {
            let _status = MessageAuthStatus::from_mail_parser(black_box(&parsed_message)).unwrap();
        })
    });

    c.bench_function("alloc_yes::DkimSignatures from_mail_parser", |b| {
        b.iter(|| {
            let _status = DkimSignatures::from_mail_parser(black_box(&parsed_message)).unwrap();
        })
    });

    let first_dkim: &HeaderValue<'_> = parsed_message
        .header_values("DKIM-Signature")
        .nth(0)
        .unwrap();

    c.bench_function("From<mail_parser::HeaderValue> for DkimSignature", |b| {
        b.iter(|| {
            let _res: DkimSignature<'_> = black_box(first_dkim).try_into().unwrap();
        })
    });

    let first_auth_result: &HeaderValue<'_> = parsed_message
        .header_values("Authentication-Results")
        .nth(0)
        .unwrap();

    c.bench_function(
        "From<mail_parser::HeaderValue> for AuthenticationResults",
        |b| {
            b.iter(|| {
                let _res: AuthenticationResults<'_> =
                    black_box(first_auth_result).try_into().unwrap();
            })
        },
    );

    #[cfg(feature = "verifier")]
    let status = MessageAuthStatus::from_mail_parser(&parsed_message).unwrap();
    #[cfg(feature = "verifier")]
    c.bench_function("ReturnPathVerifier::from_alloc_yes()", |b| {
        b.iter(|| {
            let _verifier =
                ReturnPathVerifier::from_alloc_yes(black_box(&status), &parsed_message).unwrap();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
