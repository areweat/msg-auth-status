use msg_auth_status::alloc_yes::AuthenticationResults;
use msg_auth_status::mail_parser::MessageParser;

use std::fs::File;
use std::io::Read;

fn load_test_data(file_location: &str) -> Vec<u8> {
    let mut file = File::open(file_location).unwrap();
    let mut data: Vec<u8> = vec![];
    file.read_to_end(&mut data).unwrap();
    data
}

fn main() {
    let mail_body = load_test_data("test_data/from_gmail_to_arewe_at.eml");

    // We are using mail_parser library to parse the message otherwise
    let parser = MessageParser::default();
    let parsed_message = parser.parse(&mail_body).unwrap();

    // Pick the first Authentication-Results found - we only have one so easy :)
    // In real world scenario you have many.
    let first_header = parsed_message
        .header_values("Authentication-Results")
        .nth(0)
        .expect("No Authentication-Results header present at all?");

    // Since this represents multiple results we have errors embedded potentially in each result
    let auth_res: AuthenticationResults<'_> = first_header.into();

    assert_eq!(auth_res.raw, Some("mail.localhost.horse;\n\tdkim=pass header.d=gmail.com header.s=20230601 header.b=izgHs/vK;\n\tspf=none (mail.localhost.horse: no SPF records found for postmaster@mail-oa1-x2f.google.com) smtp.helo=mail-oa1-x2f.google.com;\n\tspf=softfail (mail.localhost.horse: domain of developer.finchie@gmail.com reports soft fail for 172.17.0.1) smtp.mailfrom=developer.finchie@gmail.com;\n\tiprev=permerror (dns record not found) policy.iprev=172.17.0.1;\n\tdmarc=pass header.from=gmail.com policy.dmarc=none"));
}
