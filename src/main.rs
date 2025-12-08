#[cfg(test)]
mod tests;
mod api;
mod crypto;
mod dns;
mod parsers;
mod verify_dkim;

use crate::api::{handle_request, RequestType};
use std::io::{self, Read};

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let mut input_string = String::new();
    io::stdin().read_to_string(&mut input_string)?;

    let request: RequestType = serde_json::from_str(&input_string)?;

    let response = handle_request(request);

    print!("{}", serde_json::to_string(&response)?);
    Ok(())
}
