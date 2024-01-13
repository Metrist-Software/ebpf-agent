use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let resp = reqwest::blocking::get("https://www.google.com/")?.text()?;
    println!("{:#?}", resp);
    Ok(())
}
