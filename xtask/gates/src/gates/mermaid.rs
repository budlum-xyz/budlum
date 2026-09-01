//! Mermaid diagram gate.
//!
//! Checks every mermaid diagram in a Markdown file against the mistakes that
//! actually happened in this one, rather than against a grammar.
//!
//! Two of the fifty-one diagrams in `ARCHITECTURE.md` were wrong in ways a
//! renderer does not complain about, which is why nobody noticed:
//!
//!   * A node id declared twice with two different labels. Mermaid keeps the
//!     first label and silently drops the second, so the diagram renders,
//!     looks complete, and says something the author did not write.
//!   * A node used only on the right of an arrow, with no declaration and no
//!     other edge. Mermaid invents a node whose label is its id, so an
//!     identifier meant as a cross-reference to another diagram renders as a
//!     bare token with no meaning on the page it appears on.
//!
//! Both classes are found by reading edges, so that is what this does.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

/// One `node[Label]` occurrence, with where it was seen.
#[derive(Debug, Clone)]
struct Decl {
    label: String,
    line: usize,
}

/// A finding the gate refuses on.
#[derive(Debug)]
struct Finding {
    diagram: usize,
    heading: String,
    line: usize,
    kind: String,
    detail: String,
}

/// A mermaid block lifted out of the surrounding Markdown.
#[derive(Debug)]
struct Block {
    index: usize,
    heading: String,
    /// Source line number of each body line, so findings point at the file.
    body: Vec<(usize, String)>,
}

/// Pull every fenced mermaid block out, remembering the nearest heading.
fn blocks_of(md: &str) -> Vec<Block> {
    let mut out = Vec::new();
    let mut heading = String::from("(before any heading)");
    let mut inside = false;
    let mut body: Vec<(usize, String)> = Vec::new();

    for (i, raw) in md.lines().enumerate() {
        let line_no = i + 1;
        let trimmed = raw.trim_end();

        if !inside && trimmed.starts_with("## ") {
            heading = trimmed[3..].trim().to_string();
            continue;
        }
        if trimmed == "```mermaid" {
            inside = true;
            body = Vec::new();
            continue;
        }
        if inside && trimmed == "```" {
            inside = false;
            out.push(Block {
                index: out.len() + 1,
                heading: heading.clone(),
                body: std::mem::take(&mut body),
            });
            continue;
        }
        if inside {
            body.push((line_no, trimmed.to_string()));
        }
    }
    out
}

/// Strip an edge label written as `-->|text|` or `-. text .->` so the text
/// inside it is not mistaken for a node.
fn strip_edge_labels(line: &str) -> String {
    let mut out = String::new();
    let mut in_pipe = false;
    for c in line.chars() {
        if c == '|' {
            in_pipe = !in_pipe;
            out.push(' ');
            continue;
        }
        if !in_pipe {
            out.push(c);
        }
    }
    // Dotted edges carry their label between the dots: `-. never shared .->`.
    let mut cleaned = String::new();
    let bytes: Vec<char> = out.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == '-' && i + 1 < bytes.len() && bytes[i + 1] == '.' {
            // Skip to the closing `.-` or `.=`.
            let mut j = i + 2;
            while j + 1 < bytes.len() && !(bytes[j] == '.' && bytes[j + 1] == '-') {
                j += 1;
            }
            cleaned.push_str(" --> ");
            i = j + 2;
            continue;
        }
        cleaned.push(bytes[i]);
        i += 1;
    }
    cleaned
}

/// Is this a mermaid keyword rather than a node id?
fn is_keyword(tok: &str) -> bool {
    matches!(
        tok,
        "flowchart"
            | "graph"
            | "sequenceDiagram"
            | "stateDiagram"
            | "stateDiagram-v2"
            | "classDiagram"
            | "erDiagram"
            | "gantt"
            | "pie"
            | "journey"
            | "subgraph"
            | "end"
            | "participant"
            | "actor"
            | "note"
            | "Note"
            | "loop"
            | "alt"
            | "else"
            | "opt"
            | "par"
            | "and"
            | "rect"
            | "activate"
            | "deactivate"
            | "direction"
            | "class"
            | "classDef"
            | "style"
            | "linkStyle"
            | "click"
            | "TB"
            | "TD"
            | "BT"
            | "RL"
            | "LR"
            | "as"
            | "over"
            | "state"
            | "title"
            | "section"
            | "accTitle"
            | "accDescr"
    )
}

/// Read `id[Label]`, `id("Label")`, `id{Label}` and bare `id` out of one line.
///
/// Returns declarations (id with a label) and plain uses (id with none).
fn parse_nodes(line: &str) -> (Vec<(String, String)>, Vec<String>) {
    let mut decls = Vec::new();
    let mut uses = Vec::new();

    let chars: Vec<char> = line.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        // An identifier starts with a letter or underscore.
        if !(chars[i].is_alphabetic() || chars[i] == '_') {
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
            i += 1;
        }
        let id: String = chars[start..i].iter().collect();

        // A bracket immediately after the id makes it a declaration.
        let opener = chars.get(i).copied();
        let closer = match opener {
            Some('(') => Some(')'),
            Some('{') => Some('}'),
            // `>` opens the asymmetric `id>Label]` shape, which closes on `]`
            // like the ordinary bracket does.
            Some('[' | '>') => Some(']'),
            _ => None,
        };

        if let (Some(o), Some(c)) = (opener, closer) {
            let mut depth = 0i32;
            let label_start = i;
            let mut j = i;
            while j < chars.len() {
                if chars[j] == o {
                    depth += 1;
                } else if chars[j] == c {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                j += 1;
            }
            if j < chars.len() {
                let label: String = chars[label_start + 1..j].iter().collect();
                let label = label.trim().trim_matches('"').trim().to_string();
                if !is_keyword(&id) {
                    decls.push((id, label));
                }
                i = j + 1;
                continue;
            }
        }

        if !is_keyword(&id) {
            uses.push(id);
        }
    }
    (decls, uses)
}

/// Does this line carry an arrow, making it an edge rather than a bare node?
fn is_edge(line: &str) -> bool {
    line.contains("-->")
        || line.contains("---")
        || line.contains("==>")
        || line.contains("-.->")
        || line.contains("->>")
        || line.contains("--)")
}

fn check(block: &Block) -> Vec<Finding> {
    let mut findings = Vec::new();

    // A sequence diagram declares participants, not nodes; the two classes
    // below do not apply to it and pretending they do produces noise.
    let is_flow = block
        .body
        .iter()
        .find(|(_, l)| !l.trim().is_empty())
        .is_some_and(|(_, l)| l.starts_with("flowchart") || l.starts_with("graph"));
    if !is_flow {
        return findings;
    }

    let mut declared: BTreeMap<String, Decl> = BTreeMap::new();
    // How many times an id appears anywhere, so a node that only ever sits on
    // the right of one arrow can be told from a genuinely shared one.
    let mut mentions: BTreeMap<String, usize> = BTreeMap::new();
    let mut undeclared: BTreeMap<String, usize> = BTreeMap::new();

    for (line_no, raw) in &block.body {
        let line = raw.trim();
        if line.is_empty() || line.starts_with("%%") {
            continue;
        }
        let cleaned = strip_edge_labels(line);
        let (decls, uses) = parse_nodes(&cleaned);

        for (id, label) in decls {
            *mentions.entry(id.clone()).or_insert(0) += 1;
            match declared.get(&id) {
                Some(prev) if prev.label != label => {
                    findings.push(Finding {
                        diagram: block.index,
                        heading: block.heading.clone(),
                        line: *line_no,
                        kind: "node redeclared with a different label".into(),
                        detail: format!(
                            "`{id}` was given the label \"{}\" on line {} and \"{}\" here. \
                             Mermaid keeps the first and drops the second without a warning, \
                             so the diagram renders and says something nobody wrote. Two \
                             different things need two different ids.",
                            prev.label, prev.line, label
                        ),
                    });
                }
                Some(_) => {}
                None => {
                    declared.insert(
                        id,
                        Decl {
                            label,
                            line: *line_no,
                        },
                    );
                }
            }
        }

        for id in uses {
            *mentions.entry(id.clone()).or_insert(0) += 1;
            if !declared.contains_key(&id) {
                undeclared.entry(id).or_insert(*line_no);
            }
        }

        let _ = is_edge(line);
    }

    for (id, line) in undeclared {
        if declared.contains_key(&id) {
            continue;
        }
        // Mentioned once, never declared: mermaid invents a node labelled with
        // the id itself. That is a dangling reference, not a diagram node.
        if mentions.get(&id).copied().unwrap_or(0) <= 1 {
            findings.push(Finding {
                diagram: block.index,
                heading: block.heading.clone(),
                line,
                kind: "node used once and never declared".into(),
                detail: format!(
                    "`{id}` appears on one edge and nowhere else, and no line gives it a \
                     label. Mermaid draws a box with `{id}` written in it, so an identifier \
                     meant to point at something defined elsewhere renders as a bare token \
                     that means nothing on this page. Give it a label or drop the edge."
                ),
            });
        }
    }

    findings
}

/// Run the gate over the repository's architecture document.
///
/// # Errors
///
/// Returns the rendered findings when any diagram carries one.
/// The architecture documents this gate reads.
///
/// More than one, because the crate-level document was invisible to the gate
/// while carrying diagrams of its own: a diagram nobody checks is exactly the
/// kind that goes wrong, and the reason this gate exists is that two of the
/// main document's diagrams were wrong in ways a reader does not notice.
///
/// Each entry carries a floor. A document that suddenly reports fewer diagrams
/// than it is known to carry has usually moved or had its fences renamed, and
/// reporting OK on nothing is the failure mode a gate must not have. The floors
/// are deliberately below the current counts, so adding a diagram never needs
/// an edit here, while deleting most of them does.
///
/// A floor of zero means "check whatever is here, and do not require any".
/// The crate document is written on one branch and not another, and a gate
/// whose verdict depends on which branch it runs from is a gate that teaches
/// people to ignore it. What must not vary by branch is that the diagrams
/// present are checked; how many exist is a property of the work in progress.
const DOCUMENTS: &[(&str, usize)] = &[
    ("docs/ARCHITECTURE.md", 50),
    ("crates/agent/ARCHITECTURE.md", 0),
];

pub fn run(root: &Path) -> Result<String, String> {
    let mut total = 0usize;
    let mut all: Vec<(String, Finding)> = Vec::new();
    let mut summary: Vec<String> = Vec::new();

    for (rel, floor) in DOCUMENTS {
        let path = root.join(rel);
        let display = path.display().to_string();
        let md =
            std::fs::read_to_string(&path).map_err(|e| format!("cannot read {display}: {e}"))?;

        let blocks = blocks_of(&md);
        if blocks.len() < *floor {
            return Err(format!(
                "{display} contains {} mermaid diagram(s), fewer than the {floor} it \
                 is known to carry. Either the document moved or the fences changed, \
                 and this gate is now watching less than it was.",
                blocks.len()
            ));
        }

        total += blocks.len();
        summary.push(format!("{} in {rel}", blocks.len()));
        for b in &blocks {
            all.extend(check(b).into_iter().map(|f| (display.clone(), f)));
        }
    }

    if all.is_empty() {
        return Ok(format!(
            "Mermaid diagrams OK: {total} diagrams ({}), no node redeclared with a \
             second label and no node left dangling on one edge.",
            summary.join(", ")
        ));
    }

    let mut msg = String::new();
    let _ = writeln!(
        msg,
        "{} finding(s) across {total} mermaid diagrams.\n",
        all.len()
    );
    for (doc, f) in &all {
        let _ = writeln!(
            msg,
            "  {doc}: diagram {} ({}), line {}\n    {}\n    {}\n",
            f.diagram, f.heading, f.line, f.kind, f.detail
        );
    }
    Err(msg)
}

/// A gate nobody has tried to fool is a gate nobody should trust.
///
/// # Errors
///
/// Returns the list of canaries that did not behave.
pub fn self_test() -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();

    // The redeclaration case, which is diagram 49 as it was committed.
    let redeclared = "\
## X

```mermaid
flowchart LR
  A[Alpha] --> B[Beta]
  V[Impossible battery state rejected] --> A
  V[Zero bandwidth rejected] --> B
```
";
    let f = blocks_of(redeclared)
        .iter()
        .flat_map(check)
        .collect::<Vec<_>>();
    if f.len() != 1 || !f[0].kind.contains("redeclared") {
        problems.push(format!(
            "VACUOUS: a node redeclared with a second label was not caught: {f:?}"
        ));
    }

    // The dangling case, which is diagram 51 as it was committed.
    let dangling = "\
## Y

```mermaid
flowchart TD
  A[Alpha] --> B[Beta]
  C1 --> C1Fix[dual SHA3-256 fixed]
```
";
    let f = blocks_of(dangling)
        .iter()
        .flat_map(check)
        .collect::<Vec<_>>();
    if !f.iter().any(|x| x.kind.contains("never declared")) {
        problems.push(format!(
            "VACUOUS: a node used once and never declared was not caught: {f:?}"
        ));
    }

    // A correct diagram must pass, or the gate is a ban on diagrams.
    let good = "\
## Z

```mermaid
flowchart LR
  A[Alpha] --> B[\"Beta with spaces\"]
  B -->|labelled edge| C[Gamma]
  C -. dotted .-> A
```
";
    let f = blocks_of(good).iter().flat_map(check).collect::<Vec<_>>();
    if !f.is_empty() {
        problems.push(format!("BROKEN: a correct diagram was rejected: {f:?}"));
    }

    // The same id declared twice with the SAME label is repetition, not a
    // contradiction, and must not be reported.
    let same = "\
## W

```mermaid
flowchart LR
  A[Alpha] --> B[Beta]
  A[Alpha] --> C[Gamma]
```
";
    let f = blocks_of(same).iter().flat_map(check).collect::<Vec<_>>();
    if !f.is_empty() {
        problems.push(format!(
            "BROKEN: an id repeated with its own label was reported: {f:?}"
        ));
    }

    // A node declared once and reused bare on later edges is ordinary.
    let reuse = "\
## V

```mermaid
flowchart TD
  A[Alpha] --> B[Beta]
  B --> A
  A --> C[Gamma]
```
";
    let f = blocks_of(reuse).iter().flat_map(check).collect::<Vec<_>>();
    if !f.is_empty() {
        problems.push(format!(
            "BROKEN: a declared node reused bare was reported: {f:?}"
        ));
    }

    // Sequence diagrams declare participants; the flowchart rules do not apply.
    let seq = "\
## U

```mermaid
sequenceDiagram
  participant C as Client
  C ->> S: request
```
";
    let f = blocks_of(seq).iter().flat_map(check).collect::<Vec<_>>();
    if !f.is_empty() {
        problems.push(format!(
            "BROKEN: a sequence diagram was judged by flowchart rules: {f:?}"
        ));
    }

    if !problems.is_empty() {
        return Err(problems.join("\n  "));
    }
    Ok(String::from(
        "mermaid gate self-test OK: a node redeclared with a second label and a node used \
         once and never declared are both rejected; a correct diagram, an id repeated with \
         its own label, a declared node reused bare, and a sequence diagram all pass.",
    ))
}
