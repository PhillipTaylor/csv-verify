use clap::Parser;
use csv_verify::{build_tree_from_leaves, read_hashes_from_sha_csv, write_merkle_tree_html, Node};
use std::error::Error;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Input .sha.csv path
    sha_csv: PathBuf,

    /// Output HTML path
    output_html: PathBuf,

    /// Optional hash column index (0-based). If omitted, uses the last column.
    #[arg(long)]
    hash_col: Option<usize>,

    /// Hash prefix length used in node labels; full hash appears as tooltip.
    #[arg(long, default_value_t = 10)]
    label_len: usize,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let hashes = read_hashes_from_sha_csv(&args.sha_csv, args.hash_col)?;
    if hashes.is_empty() {
        return Err("No hashes found.".into());
    }

    let leaves: Vec<Node> = hashes.into_iter().map(|h| Node { hash: h }).collect();
    let tree = build_tree_from_leaves(leaves);

    let root = &tree.levels.last().unwrap()[0].hash;
    println!("Merkle root: {}", hex::encode(root));

    write_merkle_tree_html(&tree, &args.output_html, args.label_len)?;
    Ok(())
}

