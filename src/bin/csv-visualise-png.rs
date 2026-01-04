use clap::Parser;
use csv_verify::{build_tree_from_leaves, draw_merkle_tree_png, read_hashes_from_sha_csv, Node};
use std::error::Error;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Input .sha.csv path
    sha_csv: PathBuf,

    /// Output PNG path
    output_png: PathBuf,

    /// Optional hash column index (0-based). If omitted, uses the last column.
    #[arg(long)]
    hash_col: Option<usize>,

    #[arg(long, default_value_t = 10)]
    node_radius: i32,

    #[arg(long, default_value_t = 56)]
    x_spacing: i32,

    #[arg(long, default_value_t = 110)]
    y_spacing: i32,

    #[arg(long, default_value_t = 40)]
    padding: i32,

    #[arg(long, default_value_t = 16.0)]
    font_size: f32,

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

    draw_merkle_tree_png(
        &tree,
        &args.output_png,
        args.node_radius,
        args.x_spacing,
        args.y_spacing,
        args.padding,
        args.font_size,
        args.label_len,
    )?;

    Ok(())
}

