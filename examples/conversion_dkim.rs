use msg_auth_status::dkim::DkimSignature;
use msg_auth_status::error::DkimSignatureError;
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

    // Pick the first DKIM-Signature found - we only have one so easy :)
    // In real world scenario you have many.
    let first_header = parsed_message
        .header_values("DKIM-Signature")
        .nth(0)
        .expect("No Signature header present at all?");

    let res: Result<DkimSignature<'_>, DkimSignatureError> = first_header.try_into();

    let dkim_res = res.expect("This should have parsed OK.");

    // DKIM is always version 1 - RFCs have not updated it
    assert_eq!(dkim_res.v, msg_auth_status::dkim::DkimVersion::One);
    // DKIM Algorithm support is spotty beyond RSA / SHA-256 so this is most omnipresent
    assert_eq!(dkim_res.a, msg_auth_status::dkim::DkimAlgorithm::Rsa_Sha256);
    // DKIM canonicalization - relaxed if you're lucky.
    assert_eq!(
        dkim_res.c,
        Some(msg_auth_status::dkim::DkimCanonicalization::Relaxed)
    );
    // See the other tags from the RFC 6376
    // We can also check the raw which was:
    assert_eq!(dkim_res.raw, Some("v=1; a=rsa-sha256; c=relaxed/relaxed;\n        d=gmail.com; s=20230601; t=1718000136; x=1718604936; darn=arewe.at;\n        h=to:subject:message-id:date:from:in-reply-to:references:mime-version\n         :from:to:cc:subject:date:message-id:reply-to;\n        bh=n6uBdfYV0axK08qjFEVpSi1xB2t8jyZS3WI5QRnzhrc=;\n        b=izgHs/vKS0T/9V6B0D/Mwa6Vz5lTIJ441xTX1cXQFXjX/e+VZ5Dp1YgDxH3hA/68dr\n         HDatZ8jq2rX7mEgSoETVh+j+2APC0+lkYoK74arS8Ql/S1HYBw/M/lAl933z3pwIl/ro\n         1u51ZQVm6Nv0GlwOjDnpxOn/bGlmIE1ZNFftO4ZC7LwM5gKFLkyl+1HBSegkKy/NKu88\n         xaMF/Kd2mGkH4TtKS61bP+ha2qTly8zzb/r9IJV7gLgx64x3YNtgyqp+RFTFN9YEkhz4\n         HjHJWp9plorio/XARscYCbmH1CEvll+1qJbrHrBJ69Vizqibco96E7wi1lHQMuRVX8zq\n         3ViQ=="));

    //dbg!(&dkim_res);
}
