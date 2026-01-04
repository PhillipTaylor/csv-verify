use clap::Parser;
use csv_verify::{record_to_canonical_csv_line, sha256, sha_csv_path_for_input};
use std::error::Error;
use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Input CSV path
    input_csv: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let out_path = sha_csv_path_for_input(&args.input_csv);

    let infile = File::open(&args.input_csv)?;
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(infile);

    let outfile = File::create(&out_path)?;
    let mut wtr = csv::WriterBuilder::new()
        .has_headers(false)
        .from_writer(BufWriter::new(outfile));

    for result in rdr.records() {
        let record = result?;

        let canonical = record_to_canonical_csv_line(&record)?;
        let h = sha256(&canonical);
        let h_hex = hex::encode(h);

        let mut out_record = record.clone();
        out_record.push_field(&h_hex);

        wtr.write_record(&out_record)?;
    }

    wtr.flush()?;
    println!("{}", out_path.display());
    Ok(())
}

