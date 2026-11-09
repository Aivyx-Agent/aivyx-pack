//! `hub-check --site-dist`: scan a built site's HTML for what the Hub's
//! Content-Security-Policy (`script-src 'self'; style-src 'self'`) would
//! break, and for links into private repositories.
//!
//! A small hand-written scanner: it reads tags and their attributes, skips
//! comments, and treats `<script>`/`<style>` bodies as raw text. It is a
//! lint for a site we build ourselves, not a general HTML parser.

use std::path::{Path, PathBuf};

/// Repositories under `github.com/Aivyx-Agent/` that are private: a public
/// page must never link them.
pub const PRIVATE_REPOS: &[&str] = &[
    "aivyx-hub",
    "aivyx-verticals",
    "aivyx-ecosystem",
    "aivyx-website",
    "aivyx-brand",
    "aivyx-wallpapers",
    "aivyx-coder-bench",
    "aivyx-coder-samples",
    "aivyx-deploy",
];

/// Scan every `.html` file under `dist`. Returns one line per problem:
/// `site: <file>:<line>: <what>: <excerpt>`.
pub fn check_site(dist: &Path) -> Vec<String> {
    let mut files = Vec::new();
    if let Err(e) = collect_html(dist, &mut files) {
        return vec![format!("site: {}: {e}", dist.display())];
    }
    files.sort();
    let mut out = Vec::new();
    for file in files {
        let rel = file
            .strip_prefix(dist)
            .unwrap_or(&file)
            .display()
            .to_string();
        match std::fs::read_to_string(&file) {
            Ok(html) => {
                for (line, msg) in scan_html(&html) {
                    out.push(format!("site: {rel}:{line}: {msg}"));
                }
            }
            Err(e) => out.push(format!("site: {rel}: {e}")),
        }
    }
    out
}

fn collect_html(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let path = entry.path();
        if ft.is_dir() {
            collect_html(&path, out)?;
        } else if ft.is_file()
            && path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("html"))
        {
            out.push(path);
        }
    }
    Ok(())
}

/// A start tag: its name (lowercase) and attributes (name lowercase,
/// value as written).
struct Tag {
    name: String,
    attrs: Vec<(String, String)>,
    /// Byte range of the whole tag in the source.
    start: usize,
    end: usize,
}

/// `(line, problem)` for one HTML document.
pub fn scan_html(html: &str) -> Vec<(usize, String)> {
    let bytes = html.as_bytes();
    let line_of = |at: usize| html[..at].bytes().filter(|&b| b == b'\n').count() + 1;
    let snippet = |start: usize, end: usize| {
        let s: String = html[start..end]
            .chars()
            .map(|c| if c.is_whitespace() { ' ' } else { c })
            .collect();
        let mut e: String = s.chars().take(80).collect();
        if s.chars().count() > 80 {
            e.push('…');
        }
        e
    };
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(off) = html[i..].find('<') {
        let at = i + off;
        let rest = &html[at..];
        if let Some(comment) = rest.strip_prefix("<!--") {
            i = comment.find("-->").map_or(html.len(), |e| at + 4 + e + 3);
            continue;
        }
        if rest.starts_with("<!") || rest.starts_with("<?") || rest.starts_with("</") {
            i = rest.find('>').map_or(html.len(), |e| at + e + 1);
            continue;
        }
        if !bytes.get(at + 1).is_some_and(u8::is_ascii_alphabetic) {
            i = at + 1;
            continue;
        }
        let tag = parse_tag(html, at);
        i = tag.end;
        let excerpt = snippet(tag.start, tag.end);
        let line = line_of(tag.start);
        let has = |name: &str| tag.attrs.iter().any(|(n, _)| n == name);
        match tag.name.as_str() {
            "script" if !has("src") => out.push((
                line,
                format!("inline <script> (no src; CSP script-src 'self' blocks it): {excerpt}"),
            )),
            "style" => out.push((
                line,
                format!("inline <style> element (CSP style-src 'self' blocks it): {excerpt}"),
            )),
            _ => {}
        }
        if has("style") {
            out.push((
                line,
                format!("inline style=\"…\" attribute (CSP style-src 'self' blocks it): {excerpt}"),
            ));
        }
        for (name, value) in &tag.attrs {
            if let Some(repo) = private_repo_link(value) {
                out.push((
                    line,
                    format!("{name} links the private repo {repo}: {excerpt}"),
                ));
            }
        }
        // Script and style bodies are raw text, not markup.
        if matches!(tag.name.as_str(), "script" | "style") {
            let close = format!("</{}", tag.name);
            i = find_ci(html, i, &close).unwrap_or(html.len());
        }
    }
    out
}

/// Parse the start tag at `at` (`html[at] == '<'`).
fn parse_tag(html: &str, at: usize) -> Tag {
    let b = html.as_bytes();
    let mut i = at + 1;
    let name_start = i;
    while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'>' && b[i] != b'/' {
        i += 1;
    }
    let name = html[name_start..i].to_ascii_lowercase();
    let mut attrs = Vec::new();
    loop {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        if b[i] == b'>' {
            i += 1;
            break;
        }
        let n_start = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && !matches!(b[i], b'=' | b'>' | b'/') {
            i += 1;
        }
        let attr = html[n_start..i].to_ascii_lowercase();
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        if i < b.len() && b[i] == b'=' {
            i += 1;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
                let q = b[i];
                let v_start = i + 1;
                i = v_start;
                while i < b.len() && b[i] != q {
                    i += 1;
                }
                value = html[v_start..i.min(b.len())].to_string();
                i = (i + 1).min(b.len());
            } else {
                let v_start = i;
                while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'>' {
                    i += 1;
                }
                value = html[v_start..i].to_string();
            }
        }
        if !attr.is_empty() {
            attrs.push((attr, value));
        }
    }
    Tag {
        name,
        attrs,
        start: at,
        end: i,
    }
}

/// Case-insensitive find of an ASCII `needle` in `html[from..]`.
fn find_ci(html: &str, from: usize, needle: &str) -> Option<usize> {
    let hay = html.as_bytes();
    let n = needle.as_bytes();
    (from..hay.len().saturating_sub(n.len() - 1))
        .find(|&i| hay[i..i + n.len()].eq_ignore_ascii_case(n))
}

/// The private repo `value` links under `github.com/Aivyx-Agent/`, if any
/// (any case, with or without `www.`, with any trailing path or anchor).
pub fn private_repo_link(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    const HOST: &str = "github.com/aivyx-agent/";
    let mut from = 0;
    while let Some(off) = lower[from..].find(HOST) {
        let at = from + off;
        from = at + HOST.len();
        // `github.com` must be the host itself or a subdomain's tail
        // (`www.github.com`), not part of a longer name (`notgithub.com`).
        let before = lower[..at].bytes().next_back();
        if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == b'-') {
            continue;
        }
        let name: String = lower[from..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            .collect();
        let name = name.strip_suffix(".git").unwrap_or(&name);
        if let Some(repo) = PRIVATE_REPOS.iter().find(|r| **r == name) {
            return Some(repo);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_links() {
        for hit in [
            "https://github.com/Aivyx-Agent/aivyx-hub",
            "https://www.GitHub.com/aivyx-agent/AIVYX-HUB#status",
            "github.com/Aivyx-Agent/aivyx-verticals/blob/main/x.md",
            "https://github.com/Aivyx-Agent/aivyx-deploy.git",
            "https://github.com/Aivyx-Agent/aivyx-coder-bench?tab=readme",
        ] {
            assert!(private_repo_link(hit).is_some(), "{hit}");
        }
        for miss in [
            "https://github.com/Aivyx-Agent/aivyx-pack",
            "https://github.com/Aivyx-Agent/aivyx-coder",
            "https://github.com/Aivyx-Agent/aivyx-hub-public",
            "https://notgithub.com/Aivyx-Agent/aivyx-hub",
            "https://github.com/Other/aivyx-hub",
        ] {
            assert!(private_repo_link(miss).is_none(), "{miss}");
        }
    }

    #[test]
    fn scanner_rules() {
        let lines = |html: &str| {
            scan_html(html)
                .into_iter()
                .map(|(_, m)| m)
                .collect::<Vec<_>>()
        };
        assert!(
            lines(
                r#"<!doctype html><html><head><script type="module" src="/theme.js"></script>
            <link rel="stylesheet" href="/site.css"></head>
            <body class=x><a href="https://github.com/Aivyx-Agent/aivyx-pack">ok</a>
            <!-- <script>alert(1)</script> style="x" github.com/Aivyx-Agent/aivyx-hub -->
            </body></html>"#
            )
            .is_empty()
        );
        let found = lines("<p>\n<SCRIPT type=module>let s = '<style>';</script>");
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("inline <script>"));
        assert_eq!(scan_html("<p>\n\n<script>x</script>")[0].0, 3);
        let found = lines("<style>p{}</style>");
        assert!(found[0].contains("<style> element"), "{found:?}");
        let found = lines("<div STYLE='color:red'>");
        assert!(found[0].contains("style=\""), "{found:?}");
        let found = lines("<img src=https://github.com/aivyx-agent/aivyx-brand/raw/x.png>");
        assert!(
            found[0].contains("src links the private repo aivyx-brand"),
            "{found:?}"
        );
        let found = lines("<a title='a > b' href=\"https://github.com/Aivyx-Agent/aivyx-hub#x\">");
        assert!(found[0].contains("aivyx-hub"), "{found:?}");
    }
}
