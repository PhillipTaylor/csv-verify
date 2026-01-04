use clap::Parser;
use csv::StringRecord;
use image::{Rgb, RgbImage};
use imageproc::drawing::{draw_filled_circle_mut, draw_line_segment_mut, draw_text_mut};
use rusttype::{Font, Scale};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Input CSV path
    input_csv: PathBuf,

    /// Output file path:
    /// - if --png (default), should end with .png
    /// - if --html, should end with .html
    output: PathBuf,

    /// Emit PNG (default if neither --png nor --html is provided)
    #[arg(long, conflicts_with = "html")]
    png: bool,

    /// Emit HTML
    #[arg(long, conflicts_with = "png")]
    html: bool,

    /// Node radius in pixels (PNG mode)
    #[arg(long, default_value_t = 10)]
    node_radius: i32,

    /// Horizontal spacing between leaf nodes (PNG mode)
    #[arg(long, default_value_t = 56)]
    x_spacing: i32,

    /// Vertical spacing between levels (PNG mode)
    #[arg(long, default_value_t = 110)]
    y_spacing: i32,

    /// Padding around the drawing (PNG mode)
    #[arg(long, default_value_t = 40)]
    padding: i32,

    /// Font size for hash labels (PNG mode)
    #[arg(long, default_value_t = 16.0)]
    font_size: f32,

    /// Hash prefix length to display under each node (PNG mode + HTML label)
    #[arg(long, default_value_t = 10)]
    label_len: usize,

    /// If set, also write the Merkle root to stdout
    #[arg(long, default_value_t = true)]
    print_root: bool,
}

#[derive(Clone, Debug)]
struct Node {
    hash: [u8; 32],
}

/// Represents the whole tree with explicit parent/child links, for HTML interactivity.
#[derive(Clone, Debug)]
struct Tree {
    levels: Vec<Vec<Node>>,
    // For a node at (level, index): children are at (level-1, index*2) and (level-1, index*2+1)
    // with duplication of last if odd. For hover highlighting we compute leaf ranges.
    leaf_ranges: Vec<Vec<(usize, usize)>>, // inclusive [start,end] leaf indices contributing to node
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
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    sha256(&buf)
}

/// Canonicalise a CSV record back into a single line.
/// Uses csv writer to ensure deterministic quoting/escaping.
fn record_to_canonical_csv_line(record: &StringRecord) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut v = Vec::<u8>::new();
    {
        let mut wtr = csv::WriterBuilder::new()
            .has_headers(false)
            .from_writer(BufWriter::new(&mut v));
        wtr.write_record(record)?;
        wtr.flush()?;
    }
    Ok(v)
}

fn build_tree(leaves: Vec<Node>) -> Tree {
    let mut levels: Vec<Vec<Node>> = Vec::new();
    if leaves.is_empty() {
        return Tree {
            levels,
            leaf_ranges: vec![],
        };
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
                &prev[i].hash
            };
            next.push(Node {
                hash: hash_pair(left, right),
            });
            i += 2;
        }
        levels.push(next);
    }

    // Precompute leaf contribution ranges for each node for HTML hover.
    // Leaves are level 0; each internal node covers a contiguous range of leaves.
    let leaf_count = levels[0].len();
    let mut leaf_ranges: Vec<Vec<(usize, usize)>> = vec![vec![(0, 0); 0]; levels.len()];

    // Level 0: each leaf covers itself
    leaf_ranges[0] = (0..leaf_count).map(|i| (i, i)).collect();

    for lvl in 1..levels.len() {
        let parent_count = levels[lvl].len();
        let mut ranges = Vec::with_capacity(parent_count);
        for p in 0..parent_count {
            let c_left = p * 2;
            let c_right = p * 2 + 1;

            let (l_start, l_end) = leaf_ranges[lvl - 1][c_left];
            let (r_start, r_end) = if c_right < leaf_ranges[lvl - 1].len() {
                leaf_ranges[lvl - 1][c_right]
            } else {
                // duplicated last child => same range as left
                leaf_ranges[lvl - 1][c_left]
            };
            ranges.push((l_start.min(r_start), l_end.max(r_end)));
        }
        leaf_ranges[lvl] = ranges;
    }

    Tree { levels, leaf_ranges }
}

fn short_hex(hash: &[u8; 32], label_len: usize) -> String {
    let h = hex::encode(hash);
    if label_len >= h.len() {
        h
    } else {
        h[..label_len].to_string()
    }
}

fn draw_merkle_tree_png(
    tree: &Tree,
    out_path: &PathBuf,
    node_radius: i32,
    x_spacing: i32,
    y_spacing: i32,
    padding: i32,
    font_size: f32,
    label_len: usize,
) -> Result<(), Box<dyn Error>> {
    if tree.levels.is_empty() {
        return Err("No rows found: CSV produced zero leaves, cannot draw Merkle tree.".into());
    }

    // Load font (vendored)
    let font_bytes: &[u8] = include_bytes!("../assets/DejaVuSans.ttf");
    let font = Font::try_from_bytes(font_bytes).ok_or("Failed to load TTF font from assets/")?;
    let scale = Scale::uniform(font_size);

    let leaf_count = tree.levels[0].len() as i32;
    let level_count = tree.levels.len() as i32;

    // Canvas size: allow room for labels under nodes
    let label_extra = (font_size as i32) + 18;
    let width = (padding * 2 + (leaf_count - 1).max(0) * x_spacing + node_radius * 2).max(400);
    let height = (padding * 2
        + (level_count - 1).max(0) * y_spacing
        + node_radius * 2
        + label_extra)
        .max(300);

    let mut img = RgbImage::from_pixel(width as u32, height as u32, Rgb([255, 255, 255]));

    let edge_color = Rgb([120, 120, 120]);
    let node_color = Rgb([40, 40, 40]);
    let text_color = Rgb([0, 0, 0]);

    // Precompute node positions: positions[level][index] = (x, y)
    let mut positions: Vec<Vec<(f32, f32)>> = Vec::with_capacity(tree.levels.len());

    for (lvl, nodes) in tree.levels.iter().enumerate() {
        // Draw from top (root) to bottom (leaves)? We'll keep root near top.
        let y = (padding + (lvl as i32) * y_spacing + node_radius) as f32;

        let count = nodes.len() as i32;
        let mut lvl_pos: Vec<(f32, f32)> = Vec::with_capacity(nodes.len());

        if count == 1 {
            let x = (width / 2) as f32;
            lvl_pos.push((x, y));
        } else {
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

    // Draw edges
    for lvl in 0..(tree.levels.len().saturating_sub(1)) {
        let parent_positions = &positions[lvl];
        let child_positions = &positions[lvl + 1];

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
                let (lx, ly) = child_positions[c_left];
                draw_line_segment_mut(&mut img, (px, py), (lx, ly), edge_color);
            }
        }
    }

    // Draw nodes and labels
    for (lvl, nodes) in tree.levels.iter().enumerate() {
        for (idx, n) in nodes.iter().enumerate() {
            let (x, y) = positions[lvl][idx];
            let xi = x as i32;
            let yi = y as i32;

            draw_filled_circle_mut(&mut img, (xi, yi), node_radius, node_color);

            // Label under node: short hash prefix
            let label = short_hex(&n.hash, label_len);

            // crude centering: assume ~0.6 * font_size per char
            let approx_char_w = (font_size * 0.6) as i32;
            let text_w = approx_char_w * (label.len() as i32);
            let tx = (xi - text_w / 2).max(0);
            let ty = yi + node_radius + 6;

            draw_text_mut(&mut img, text_color, tx, ty, scale, &font, &label);
        }
    }

    img.save(out_path)?;
    Ok(())
}

fn write_merkle_tree_html(tree: &Tree, out_path: &PathBuf, label_len: usize) -> Result<(), Box<dyn Error>> {
    if tree.levels.is_empty() {
        return Err("No rows found: CSV produced zero leaves, cannot render HTML Merkle tree.".into());
    }

    let levels = &tree.levels;
    let leaf_count = levels[0].len();

    // We'll render root at top (highest level index), leaves at bottom, as rows of divs.
    // For hover highlighting: each node gets data-leaf-start/end, and we highlight all leaves in that range.
    // This guarantees "all child divs that make the hash up" even if internal nodes are duplicated in odd cases.
    // Additionally, we highlight internal nodes whose ranges are within the hovered range.

    // Build a flat list of node metadata for HTML ids.
    // We'll assign ids: n-L{lvl}-I{idx}
    // Note: HTML levels drawn from root->leaves, but our tree.levels is leaves->root.
    // We'll invert for display.
    let display_levels: Vec<usize> = (0..levels.len()).rev().collect();

    let mut html = String::new();
    html.push_str(r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Merkle Tree</title>
<style>
  :root { --gap: 18px; --nodeW: 120px; --nodeH: 44px; }
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; background: #fff; color:#111; }
  .container { display: flex; flex-direction: column; gap: 26px; }
  .level { display: flex; justify-content: center; gap: var(--gap); flex-wrap: nowrap; overflow-x: auto; padding-bottom: 6px; }
  .node {
    width: var(--nodeW);
    height: var(--nodeH);
    border: 1px solid #bbb;
    border-radius: 10px;
    display:flex;
    align-items:center;
    justify-content:center;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    font-size: 14px;
    user-select: none;
    background: #fafafa;
    transition: background .12s, border-color .12s, box-shadow .12s, transform .12s;
    box-sizing: border-box;
  }
  .node:hover { transform: translateY(-1px); border-color: #888; }
  .node.active { background: #fff3bf; border-color: #d19a00; box-shadow: 0 0 0 2px rgba(209,154,0,0.20); }
  .node.leaf { background: #f7fbff; }
  .legend { font-size: 13px; color:#444; margin-bottom: 10px; line-height: 1.35; }
  .rootLine { margin: 0 0 14px; font-size: 13px; color:#222; }
  .rootHash { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
</style>
</head>
<body>
"#);

    let root_hash = hex::encode(&levels.last().unwrap()[0].hash);
    html.push_str(&format!(
        r#"<div class="rootLine"><strong>Merkle root:</strong> <span class="rootHash">{}</span></div>"#,
        root_hash
    ));

    html.push_str(&format!(
        r#"<div class="legend">
Hover any node to highlight all descendant leaves that contribute to that hash (and any internal nodes fully contained in that leaf range).
Leaf count: {}.
</div>"#,
        leaf_count
    ));

    html.push_str(r#"<div class="container">"#);

    for (row_idx, &lvl) in display_levels.iter().enumerate() {
        // lvl is index in tree.levels (0=leaves)
        let nodes = &levels[lvl];
        let ranges = &tree.leaf_ranges[lvl];

        html.push_str(r#"<div class="level">"#);
        for (idx, node) in nodes.iter().enumerate() {
            let id = format!("n-L{}-I{}", lvl, idx);
            let (ls, le) = ranges[idx];
            let label = short_hex(&node.hash, label_len);
            let is_leaf = lvl == 0;
            let cls = if is_leaf { "node leaf" } else { "node" };
            // Title shows full hash on hover
            let title = hex::encode(&node.hash);
            html.push_str(&format!(
                r#"<div class="{cls}" id="{id}" data-lvl="{lvl}" data-idx="{idx}" data-leaf-start="{ls}" data-leaf-end="{le}" title="{title}">{label}</div>"#
            ));
        }
        html.push_str(r#"</div>"#);

        // Optional: add extra spacing after root row
        if row_idx == 0 {
            html.push_str(r#"<div style="height:8px"></div>"#);
        }
    }

    html.push_str(r#"</div>"#);

    // JS hover behaviour:
    // - On hover over a node, read its leaf range [s,e]
    // - Mark leaf nodes whose leaf index in [s,e] active
    // - Mark internal nodes whose range is subset of [s,e] active
    html.push_str(r#"
<script>
(function() {
  const nodes = Array.from(document.querySelectorAll('.node'));

  function clearActive() {
    nodes.forEach(n => n.classList.remove('active'));
  }

  function activateRange(s, e) {
    nodes.forEach(n => {
      const ns = parseInt(n.dataset.leafStart, 10);
      const ne = parseInt(n.dataset.leafEnd, 10);

      // Leaf nodes: highlight if within range.
      // Internal nodes: highlight if fully contained in range.
      const isLeaf = n.classList.contains('leaf');
      const inRange = isLeaf ? (ns >= s && ne <= e) : (ns >= s && ne <= e);

      if (inRange) n.classList.add('active');
    });
  }

  nodes.forEach(n => {
    n.addEventListener('mouseenter', () => {
      const s = parseInt(n.dataset.leafStart, 10);
      const e = parseInt(n.dataset.leafEnd, 10);
      clearActive();
      activateRange(s, e);
    });
  });

  document.body.addEventListener('mouseleave', () => clearActive());
})();
</script>
</body>
</html>
"#);

    fs::write(out_path, html)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    // Default mode: PNG if neither explicitly set
    let mode_png = args.png || (!args.png && !args.html);
    let mode_html = args.html;

    let file = File::open(&args.input_csv)?;
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(file);

    let mut leaves: Vec<Node> = Vec::new();

    for result in rdr.records() {
        let record = result?;
        let canonical = record_to_canonical_csv_line(&record)?;
        let h = sha256(&canonical);
        leaves.push(Node { hash: h });
    }

    let tree = build_tree(leaves);

    if tree.levels.is_empty() {
        return Err("CSV produced zero records; no Merkle tree to build.".into());
    }

    let root = &tree.levels.last().unwrap()[0].hash;
    if args.print_root {
        println!("Merkle root (SHA-256 hex): {}", hex::encode(root));
        println!("Levels: {}", tree.levels.len());
        println!("Leaf count: {}", tree.levels[0].len());
    }

    if mode_png {
        draw_merkle_tree_png(
            &tree,
            &args.output,
            args.node_radius,
            args.x_spacing,
            args.y_spacing,
            args.padding,
            args.font_size,
            args.label_len,
        )?;
    } else if mode_html {
        write_merkle_tree_html(&tree, &args.output, args.label_len)?;
    } else {
        return Err("No mode selected. Use --png or --html.".into());
    }

    Ok(())
}

