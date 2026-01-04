use csv::StringRecord;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Node {
    pub hash: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct Tree {
    /// levels[0] = leaves, levels[last][0] = root
    pub levels: Vec<Vec<Node>>,
    /// leaf_ranges[level][idx] = inclusive [start,end] leaf indices contributing to node
    pub leaf_ranges: Vec<Vec<(usize, usize)>>,
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    sha256(&buf)
}

/// Canonicalise a CSV record back into a single line.
/// Uses csv writer for deterministic quoting/escaping; includes trailing newline.
pub fn record_to_canonical_csv_line(record: &StringRecord) -> Result<Vec<u8>, Box<dyn Error>> {
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

/// Given leaves, build Merkle levels and leaf contribution ranges.
/// Convention: internal hash = SHA256(left || right), duplicate last on odd counts.
pub fn build_tree_from_leaves(leaves: Vec<Node>) -> Tree {
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

    // Leaf contribution ranges
    let leaf_count = levels[0].len();
    let mut leaf_ranges: Vec<Vec<(usize, usize)>> = vec![Vec::new(); levels.len()];

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
                leaf_ranges[lvl - 1][c_left] // duplicated
            };

            ranges.push((l_start.min(r_start), l_end.max(r_end)));
        }

        leaf_ranges[lvl] = ranges;
    }

    Tree { levels, leaf_ranges }
}

pub fn short_hex(hash: &[u8; 32], label_len: usize) -> String {
    let h = hex::encode(hash);
    if label_len >= h.len() {
        h
    } else {
        h[..label_len].to_string()
    }
}

/// Produce "<input>.<ext>.sha.csv" where ext is the original extension or "csv".
/// Example: sample.csv -> sample.csv.sha.csv, sample.tsv -> sample.tsv.sha.csv
pub fn sha_csv_path_for_input(input: &Path) -> PathBuf {
    let mut p = input.to_path_buf();
    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("csv");
    p.set_extension(format!("{ext}.sha.csv"));
    p
}

/// Read a .sha.csv (or any CSV) and return the hash from a chosen column:
/// - if hash_col is Some(i): use that index
/// - else: use last column
/// Validates each hash is 64 hex chars and decodes to 32 bytes.
pub fn read_hashes_from_sha_csv(
    sha_csv: &Path,
    hash_col: Option<usize>,
) -> Result<Vec<[u8; 32]>, Box<dyn Error>> {
    let file = std::fs::File::open(sha_csv)?;
    let mut rdr = csv::ReaderBuilder::new().has_headers(false).from_reader(file);

    let mut out: Vec<[u8; 32]> = Vec::new();

    for (row_idx, result) in rdr.records().enumerate() {
        let rec = result?;
        if rec.len() == 0 {
            return Err(format!("Row {} is empty; cannot read hash column.", row_idx + 1).into());
        }
        let col = hash_col.unwrap_or(rec.len() - 1);
        if col >= rec.len() {
            return Err(format!(
                "Row {} has {} columns; requested hash column {} is out of range.",
                row_idx + 1,
                rec.len(),
                col
            )
            .into());
        }
        let s = rec.get(col).unwrap().trim();
        if s.len() != 64 {
            return Err(format!(
                "Row {} hash value length is {}; expected 64 hex chars.",
                row_idx + 1,
                s.len()
            )
            .into());
        }
        let bytes = hex::decode(s).map_err(|e| {
            format!(
                "Row {} hash is not valid hex ({}): {}",
                row_idx + 1,
                s,
                e
            )
        })?;
        if bytes.len() != 32 {
            return Err(format!("Row {} decoded hash is not 32 bytes.", row_idx + 1).into());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        out.push(arr);
    }

    Ok(out)
}

/// Write HTML visualisation with hover highlighting of contributing leaves.
pub fn write_merkle_tree_html(tree: &Tree, out_path: &Path, label_len: usize) -> Result<(), Box<dyn Error>> {
    if tree.levels.is_empty() {
        return Err("No leaves; cannot render HTML.".into());
    }

    let levels = &tree.levels;
    let leaf_count = levels[0].len();
    let root_hash = hex::encode(&levels.last().unwrap()[0].hash);

    let display_levels: Vec<usize> = (0..levels.len()).rev().collect();

    let mut html = String::new();
    html.push_str(r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Merkle Tree</title>
<style>
  :root { --gap: 18px; --nodeW: 140px; --nodeH: 48px; }
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

    for &lvl in &display_levels {
        let nodes = &levels[lvl];
        let ranges = &tree.leaf_ranges[lvl];

        html.push_str(r#"<div class="level">"#);
        for (idx, node) in nodes.iter().enumerate() {
            let (ls, le) = ranges[idx];
            let label = short_hex(&node.hash, label_len);
            let title = hex::encode(&node.hash);
            let cls = if lvl == 0 { "node leaf" } else { "node" };
            html.push_str(&format!(
                r#"<div class="{cls}" data-leaf-start="{ls}" data-leaf-end="{le}" title="{title}">{label}</div>"#
            ));
        }
        html.push_str(r#"</div>"#);
    }

    html.push_str(r#"</div>"#);

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
      // Leaves and internal nodes are both represented by leaf ranges.
      // Highlight any node whose leaf range is fully contained in [s,e].
      if (ns >= s && ne <= e) n.classList.add('active');
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

//
// PNG drawing kept in lib for reuse by the dedicated binary.
//
pub fn draw_merkle_tree_png(
    tree: &Tree,
    out_path: &Path,
    node_radius: i32,
    x_spacing: i32,
    y_spacing: i32,
    padding: i32,
    font_size: f32,
    label_len: usize,
) -> Result<(), Box<dyn Error>> {
    use image::{Rgb, RgbImage};
    use imageproc::drawing::{draw_filled_circle_mut, draw_line_segment_mut, draw_text_mut};
    use rusttype::{Font, Scale};

    if tree.levels.is_empty() {
        return Err("No leaves; cannot draw PNG.".into());
    }

    let font_bytes: &[u8] = include_bytes!("../assets/DejaVuSans.ttf");
    let font = Font::try_from_bytes(font_bytes).ok_or("Failed to load TTF font from assets/")?;
    let scale = Scale::uniform(font_size);

    let leaf_count = tree.levels[0].len() as i32;
    let level_count = tree.levels.len() as i32;

    let label_extra = (font_size as i32) + 22;
    let width = (padding * 2 + (leaf_count - 1).max(0) * x_spacing + node_radius * 2).max(500);
    let height = (padding * 2
        + (level_count - 1).max(0) * y_spacing
        + node_radius * 2
        + label_extra)
        .max(350);

    let mut img = RgbImage::from_pixel(width as u32, height as u32, Rgb([255, 255, 255]));

    let edge_color = Rgb([120, 120, 120]);
    let node_color = Rgb([40, 40, 40]);
    let text_color = Rgb([0, 0, 0]);

    // positions[level][index]
    let mut positions: Vec<Vec<(f32, f32)>> = Vec::with_capacity(tree.levels.len());

    for (lvl, nodes) in tree.levels.iter().enumerate() {
        let y = (padding + (lvl as i32) * y_spacing + node_radius) as f32;

        let count = nodes.len() as i32;
        let mut lvl_pos: Vec<(f32, f32)> = Vec::with_capacity(nodes.len());

        if count == 1 {
            lvl_pos.push(((width / 2) as f32, y));
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

    // edges (parent lvl -> child lvl+1)
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

    // nodes + labels
    for (lvl, nodes) in tree.levels.iter().enumerate() {
        for (idx, n) in nodes.iter().enumerate() {
            let (x, y) = positions[lvl][idx];
            let xi = x as i32;
            let yi = y as i32;

            draw_filled_circle_mut(&mut img, (xi, yi), node_radius, node_color);

            let label = short_hex(&n.hash, label_len);

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

