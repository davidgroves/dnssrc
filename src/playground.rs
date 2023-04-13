use std::str::FromStr;
use trust_dns_client::rr::{LowerName, Name};

fn main() {
    let example_com = LowerName::from(Name::from_str("example.com").unwrap());    
}