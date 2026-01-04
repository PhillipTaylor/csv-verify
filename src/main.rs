use clap::Parser;
use csv::StringRecord;
use image::{Rgb, RgbImage};
use imageproc::drawing::{draw_filled_circle_mut, draw_line_segment_mut};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

/// Read a CSV row-by-row, hash each row, build a Merkle tree, and save a PNG visualization.
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Input CSV path
    input_csv: PathBuf,

    /// Output PNG path
    output_png: PathBuf,

    /// Node radius in pixels
    #[arg(long, default_value_t = 10)]
    node_radius: i32,

    /// Horizontal spacing between leaf nodes in pixels
    #[arg(long, default_value_t = 36)]
    x_spacing: i32,

    /// Vertical spacing between levels in pixels
    #[arg(long, default_value_t = 80)]
    y_spacing: i32,

    /// Padding around the drawing in pixels
    #[arg(long, default_value_t = 30)]
    padding: i32,

    /// If set, also write the Merkle root to stdout
    #[arg(long, default_value_t = true)]
    print_root: bool,
}

#[derive(Clone, Debug)]
struct Node {
    hash: [u8; 32],
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    // Internal node hash = SHA256(left || right)
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    sha256(&buf)
}

/// Canonicalise a CSV record back into a single line.
/// This uses the `csv` writer to ensure proper escaping/quoting.
fn record_to_canonical_csv_line(record: &StringRecord) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut v = Vec::<u8>::new();
    {
        let mut wtr = csv::WriterBuilder::new()
            .has_headers(false)
            .from_writer(BufWriter::new(&mut v));
        wtr.write_record(record)?;
        wtr.flush()?;
    }
    // csv::Writer includes a trailing newline; keep it (it is deterministic).
    Ok(v)
}

fn build_merkle_levels(leaves: Vec<Node>) -> Vec<Vec<Node>> {
    // levels[0] = leaves
    // levels[last][0] = root
    let mut levels: Vec<Vec<Node>> = Vec::new();
    if leaves.is_empty() {
        return levels;
    }
    levels.push(leaves);

    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let mut next: Vec<Node> = Vec::with_capacity((prev.len() + 1) / 2);

        let mut i = 0usize;
        while i < prev.len() {
            let left = &prev[i].hash;
            let right = if i + 1 < prev.len() {
                &prev[i + 1].hash
            } else {
                // Duplicate last if odd
                &prev[i].hash
            };
            next.push(Node {
                hash: hash_pair(left, right),
            });
            i += 2;
        }
        levels.push(next);
    }

    levels
}

fn draw_merkle_tree_png(
    levels: &[Vec<Node>],
    out_path: &PathBuf,
    node_radius: i32,
    x_spacing: i32,
    y_spacing: i32,
    padding: i32,
) -> Result<(), Box<dyn Error>> {
    if levels.is_empty() {
        return Err("No rows found: CSV produced zero leaves, cannot draw Merkle tree.".into());
    }

    let leaf_count = levels[0].len() as i32;
    let level_count = levels.len() as i32;

    // Compute canvas size.
    // Width based on leaves; height based on number of levels.
    let width = (padding * 2 + (leaf_count - 1).max(0) * x_spacing + node_radius * 2).max(200);
    let height = (padding * 2 + (level_count - 1).max(0) * y_spacing + node_radius * 2).max(200);

    let mut img = RgbImage::from_pixel(width as u32, height as u32, Rgb([255, 255, 255]));

    let edge_color = Rgb([120, 120, 120]);
    let node_color = Rgb([40, 40, 40]);

    // Precompute node positions: positions[level][index] = (x, y)
    let mut positions: Vec<Vec<(f32, f32)>> = Vec::with_capacity(levels.len());

    for (lvl, nodes) in levels.iter().enumerate() {
        let y = (padding + (level_count - 1 - lvl as i32) * y_spacing + node_radius) as f32;

        let count = nodes.len() as i32;
        let mut lvl_pos: Vec<(f32, f32)> = Vec::with_capacity(nodes.len());

        if count == 1 {
            // Root centered
            let x = (width / 2) as f32;
            lvl_pos.push((x, y));
        } else {
            // Space nodes evenly across the span used by leaves,
            // aligned so that leaves are at x = padding + i*x_spacing + node_radius
            // and upper levels are interpolated across the same span.
            let left_x = (padding + node_radius) as f32;
            let right_x = (padding + node_radius + (leaf_count - 1).max(0) * x_spacing) as f32;
            let span = (right_x - left_x).max(1.0);

            for i in 0..count {
                let t = i as f32 / (count - 1) as f32;
                let x = left_x + t * span;
                lvl_pos.push((x, y));
            }
        }

        positions.push(lvl_pos);
    }

    // Draw edges first (so nodes sit on top)
    for lvl in 0..(levels.len().saturating_sub(1)) {
        let child_positions = &positions[lvl];
        let parent_positions = &positions[lvl + 1];

        // Each parent connects to two children (or one duplicated last)
        for (p_idx, &(px, py)) in parent_positions.iter().enumerate() {
            let c_left = p_idx * 2;
            let c_right = p_idx * 2 + 1;

            if c_left < child_positions.len() {
                let (lx, ly) = child_positions[c_left];
                draw_line_segment_mut(&mut img, (px, py), (lx, ly), edge_color);
            }
            if c_right < child_positions.len() {
                let (rx, ry) = child_positions[c_right];
                draw_line_segment_mut(&mut img, (px, py), (rx, ry), edge_color);
            } else if c_left < child_positions.len() {
                // If odd, connect to the last child again (visual hint of duplication)
                let (lx, ly) = child_positions[c_left];
                draw_line_segment_mut(&mut img, (px, py), (lx, ly), edge_color);
            }
        }
    }

    // Draw nodes
    for (lvl, nodes) in levels.iter().enumerate() {
        for (idx, _n) in nodes.iter().enumerate() {
            let (x, y) = positions[lvl][idx];
            draw_filled_circle_mut(&mut img, (x as i32, y as i32), node_radius, node_color);
        }
    }

    img.save(out_path)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let file = File::open(&args.input_csv)?;
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false) // treat every row as data; adjust if you want to skip headers
        .from_reader(file);

    let mut leaves: Vec<Node> = Vec::new();

    for result in rdr.records() {
        let record = result?;
        let canonical = record_to_canonical_csv_line(&record)?;
        let h = sha256(&canonical);
        leaves.push(Node { hash: h });
    }

    let levels = build_merkle_levels(leaves);

    if levels.is_empty() {
        return Err("CSV produced zero records; no Merkle tree to build.".into());
    }

    let root = &levels.last().unwrap()[0].hash;
    if args.print_root {
        println!("Merkle root (SHA-256 hex): {}", hex::encode(root));
        println!("Levels: {}", levels.len());
        println!("Leaf count: {}", levels[0].len());
    }

    draw_merkle_tree_png(
        &levels,
        &args.output_png,
        args.node_radius,
        args.x_spacing,
        args.y_spacing,
        args.padding,
    )?;

    Ok(())
}

