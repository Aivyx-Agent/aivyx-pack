//! `hub-check --site-dist`: scan a built site's pages for what the Hub's
//! Content-Security-Policy (`script-src 'self'; style-src 'self'`) would
//! break, and for links into private repositories.
//!
//! A small hand-written scanner: it reads tags and their attributes, skips
//! comments, and treats `<script>`/`<style>` bodies as raw text. Attribute
//! values and text are entity-decoded before the private-link match. It is
//! a lint for a site we build ourselves, not a general HTML parser.

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

/// Hosts (lowercase, with the org) whose next path segment is a repo name.
/// `githubusercontent.com` covers `raw.githubusercontent.com`.
const REPO_HOSTS: &[&str] = &[
    "github.com/aivyx-agent/",
    "githubusercontent.com/aivyx-agent/",
];

/// The page types scanned.
const PAGE_EXTENSIONS: &[&str] = &["html", "htm", "xhtml", "svg"];

/// `<script type>` values that mean JavaScript (an absent type does too).
const JS_TYPES: &[&str] = &[
    "",
    "module",
    "text/javascript",
    "application/javascript",
    "text/ecmascript",
    "application/ecmascript",
    "application/x-javascript",
];

/// Scan every page (`.html`, `.htm`, `.xhtml`, `.svg`) under `dist`.
/// Returns one line per problem: `site: <file>:<line>: <what>: <excerpt>`.
/// A folder with no pages is itself a problem (a wrong path must not pass).
pub fn check_site(dist: &Path) -> Vec<String> {
    let mut files = Vec::new();
    if let Err(e) = collect_pages(dist, &mut files) {
        return vec![format!("site: {}: {e}", dist.display())];
    }
    if files.is_empty() {
        return vec![format!(
            "site: {}: no .html, .htm, .xhtml or .svg files found (is this the built site?)",
            dist.display()
        )];
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

fn collect_pages(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let path = entry.path();
        if ft.is_dir() {
            collect_pages(&path, out)?;
        } else if ft.is_file()
            && path
                .extension()
                .is_some_and(|e| PAGE_EXTENSIONS.iter().any(|x| e.eq_ignore_ascii_case(x)))
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

impl Tag {
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

fn excerpt(s: &str) -> String {
    let s: String = s
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect();
    let s = s.trim();
    let mut e: String = s.chars().take(80).collect();
    if s.chars().count() > 80 {
        e.push('…');
    }
    e
}

/// `(line, problem)` for one page.
pub fn scan_html(html: &str) -> Vec<(usize, String)> {
    let bytes = html.as_bytes();
    let line_of = |at: usize| html[..at].bytes().filter(|&b| b == b'\n').count() + 1;
    let mut out = Vec::new();
    // Private links in a run of text (decoded or raw), reported at `at`.
    // (Lines: the run's start line plus the newlines before the match, so
    // a decoded run stays close enough to the source.)
    let text_links = |out: &mut Vec<(usize, String)>, text: &str, at: usize, what: &str| {
        for (repo, pos) in private_repo_links(text) {
            let line = line_of(at) + text[..pos].matches('\n').count();
            out.push((
                line,
                format!(
                    "{what} links the private repo {repo}: {}",
                    excerpt(&text[pos..])
                ),
            ));
        }
    };
    let mut i = 0;
    loop {
        let next = html[i..].find('<').map(|o| i + o);
        let text_end = next.unwrap_or(html.len());
        if text_end > i {
            text_links(&mut out, &decode_entities(&html[i..text_end]), i, "text");
        }
        let Some(at) = next else { break };
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
        let ex = excerpt(&html[tag.start..tag.end]);
        let line = line_of(tag.start);
        match tag.name.as_str() {
            // SVG scripts name their file with `href` / `xlink:href`.
            "script"
                if ["src", "href", "xlink:href"]
                    .iter()
                    .all(|a| tag.attr(a).is_none_or(|s| s.trim().is_empty())) =>
            {
                let ty = tag.attr("type").unwrap_or("").trim().to_ascii_lowercase();
                out.push((
                    line,
                    if JS_TYPES.contains(&ty.as_str()) {
                        format!("inline <script> (no src; CSP script-src 'self' blocks it): {ex}")
                    } else {
                        format!("inline data script (type={ty}); serve it as a file: {ex}")
                    },
                ));
            }
            "style" => out.push((
                line,
                format!("inline <style> element (CSP style-src 'self' blocks it): {ex}"),
            )),
            _ => {}
        }
        for (name, value) in &tag.attrs {
            let value = decode_entities(value);
            if name == "style" {
                out.push((
                    line,
                    format!("inline style=\"…\" attribute (CSP style-src 'self' blocks it): {ex}"),
                ));
            }
            if name.len() > 2 && name.starts_with("on") {
                out.push((
                    line,
                    format!("inline event handler {name}= (CSP script-src 'self' blocks it): {ex}"),
                ));
            }
            if is_url_attr(name) && url_values(name, &value).any(is_javascript_url) {
                out.push((line, format!("{name} is a javascript: URL: {ex}")));
            }
            for (repo, _) in private_repo_links(&value) {
                out.push((line, format!("{name} links the private repo {repo}: {ex}")));
            }
        }
        // Script and style bodies are raw text, not markup: scan them for
        // private links as written and as decoded.
        if matches!(tag.name.as_str(), "script" | "style") {
            let close = format!("</{}", tag.name);
            let end = find_ci(html, i, &close).unwrap_or(html.len());
            let body = &html[i..end];
            let what = format!("<{}> body", tag.name);
            let raw = private_repo_links(body);
            if raw.is_empty() {
                text_links(&mut out, &decode_entities(body), i, &what);
            } else {
                text_links(&mut out, body, i, &what);
            }
            i = end;
        }
    }
    out
}

/// Attributes whose value is a URL (or, for `srcset`, a list of them).
const URL_ATTRS: &[&str] = &[
    "href",
    "src",
    "action",
    "formaction",
    "xlink:href",
    "data",
    "poster",
    "cite",
    "background",
    "srcset",
];

fn is_url_attr(name: &str) -> bool {
    URL_ATTRS.contains(&name)
}

/// The URLs in a URL attribute's value: the value itself, or for `srcset`
/// the first word of each comma-separated candidate.
fn url_values<'a>(name: &str, value: &'a str) -> Box<dyn Iterator<Item = &'a str> + 'a> {
    if name == "srcset" {
        Box::new(
            value
                .split(',')
                .map(|c| c.split_whitespace().next().unwrap_or("")),
        )
    } else {
        Box::new(std::iter::once(value))
    }
}

/// A `javascript:` URL, as a browser reads it: ASCII whitespace and control
/// characters inside the scheme are ignored, any case.
fn is_javascript_url(value: &str) -> bool {
    let squeezed: String = value
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && !c.is_ascii_control())
        .take(11)
        .collect();
    squeezed.eq_ignore_ascii_case("javascript:")
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

/// Decode the character references a link could hide behind: numeric
/// (`&#47;`, `&#x2F;`, with or without the `;`) and the named `&sol;`,
/// `&period;`, `&colon;`, `&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`. One
/// pass, as a browser does (`&amp;#47;` is the text `&#47;`).
pub fn decode_entities(s: &str) -> String {
    const NAMED: &[(&str, char)] = &[
        ("sol;", '/'),
        ("period;", '.'),
        ("colon;", ':'),
        ("amp;", '&'),
        ("lt;", '<'),
        ("gt;", '>'),
        ("quot;", '"'),
        ("apos;", '\''),
    ];
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        if let Some(num) = after.strip_prefix('#') {
            let (hex, digits) = match num.strip_prefix(['x', 'X']) {
                Some(h) => (true, h),
                None => (false, num),
            };
            let len = digits
                .bytes()
                .take_while(|b| {
                    if hex {
                        b.is_ascii_hexdigit()
                    } else {
                        b.is_ascii_digit()
                    }
                })
                .count();
            let code = u32::from_str_radix(&digits[..len], if hex { 16 } else { 10 }).ok();
            if let Some(c) = code.filter(|_| len > 0).and_then(char::from_u32) {
                out.push(c);
                let consumed = 1 + usize::from(hex) + len;
                let semi = usize::from(after[consumed..].starts_with(';'));
                rest = &after[consumed + semi..];
                continue;
            }
        } else if let Some((name, c)) = NAMED
            .iter()
            // Compare bytes: `after` may start with a multibyte character,
            // so it is sliced only after an (ASCII) name has matched.
            .find(|(n, _)| {
                after
                    .as_bytes()
                    .get(..n.len())
                    .is_some_and(|b| b.eq_ignore_ascii_case(n.as_bytes()))
            })
        {
            out.push(*c);
            rest = &after[name.len()..];
            continue;
        }
        out.push('&');
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Every private repo `text` links under `github.com/Aivyx-Agent/` or
/// `raw.githubusercontent.com/Aivyx-Agent/` (any case, with or without
/// `www.`, with any trailing path or anchor), with the byte offset where
/// the host starts.
pub fn private_repo_links(text: &str) -> Vec<(&'static str, usize)> {
    let lower = text.to_ascii_lowercase();
    let mut found = Vec::new();
    for host in REPO_HOSTS {
        let mut from = 0;
        while let Some(off) = lower[from..].find(host) {
            let at = from + off;
            from = at + host.len();
            // The host itself or a subdomain's tail (`www.github.com`,
            // `raw.githubusercontent.com`), not part of a longer name
            // (`notgithub.com`).
            let before = lower[..at].bytes().next_back();
            if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == b'-') {
                continue;
            }
            let name: String = lower[from..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                .collect();
            // Prose punctuation after a link (`…/aivyx-hub.`) is not part of
            // the name.
            let name = name.trim_end_matches(['.', ',', ')', ']', '"', '\'']);
            let name = name.strip_suffix(".git").unwrap_or(name);
            if let Some(repo) = PRIVATE_REPOS.iter().find(|r| **r == name) {
                found.push((*repo, at));
            }
        }
    }
    found.sort_by_key(|(_, at)| *at);
    found
}

/// The first private repo `value` links, if any.
pub fn private_repo_link(value: &str) -> Option<&'static str> {
    private_repo_links(value).first().map(|(r, _)| *r)
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
            "https://raw.githubusercontent.com/Aivyx-Agent/aivyx-brand/main/logo.svg",
            "see https://github.com/Aivyx-Agent/aivyx-hub.",
            "(github.com/Aivyx-Agent/aivyx-hub.git),",
            "github.com/Aivyx-Agent/aivyx-hub...",
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
    fn entities_are_decoded() {
        assert_eq!(
            decode_entities("https&colon;&sol;&sol;github&period;com&#47;x&#x2F;y&#47z&amp;w"),
            "https://github.com/x/y/z&w"
        );
        assert_eq!(
            decode_entities("&amp;#47; &bogus; &#; & &#x;"),
            "&#47; &bogus; &#; & &#x;"
        );
        assert_eq!(decode_entities("caf\u{e9} &#233;"), "caf\u{e9} \u{e9}");
    }

    #[test]
    fn non_ascii_after_an_ampersand_never_panics() {
        for (input, want) in [
            ("Smith&Co\u{e9}", "Smith&Co\u{e9}"),
            ("R&D\u{e9}", "R&D\u{e9}"),
            ("M\u{fc}ller&S\u{f6}hne", "M\u{fc}ller&S\u{f6}hne"),
            ("&\u{e9}", "&\u{e9}"),
            ("a&", "a&"),
            ("a&#", "a&#"),
            ("&#x", "&#x"),
            ("&#xZZ;", "&#xZZ;"),
            ("&#99999999;", "&#99999999;"),
            ("&#99999999999999999999;", "&#99999999999999999999;"),
            ("&#x110000;", "&#x110000;"),
        ] {
            assert_eq!(decode_entities(input), want, "{input:?}");
        }
        for page in [
            "<p>Smith&Co\u{e9}</p>",
            "<a title=\"R&D\u{e9}\">",
            "<p>M\u{fc}ller&S\u{f6}hne&",
        ] {
            assert!(scan_html(page).is_empty(), "{page:?}");
        }
    }

    #[test]
    fn scan_html_never_panics_on_random_input() {
        // A small xorshift, seeded, so a failure is reproducible.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        const PIECES: &[&str] = &[
            "&",
            "<",
            ">",
            "\"",
            "'",
            "=",
            "#",
            "x",
            ";",
            "/",
            "-",
            " ",
            "\n",
            "\u{e9}",
            "\u{fc}",
            "\u{4e2d}",
            "\u{1f600}",
            "&#",
            "&#x",
            "&amp",
            "&sol",
            "<!--",
            "-->",
            "<script",
            "</script",
            "<style",
            "<a href=",
            "style=",
            "onclick=",
            "javascript:",
            "github.com/Aivyx-Agent/aivyx-hub",
            "1",
            "F",
        ];
        for _ in 0..500 {
            let len = (next() % 40) as usize;
            let input: String = (0..len)
                .map(|_| PIECES[(next() % PIECES.len() as u64) as usize])
                .collect();
            let _ = scan_html(&input);
            let _ = decode_entities(&input);
            let _ = private_repo_links(&input);
        }
    }

    #[test]
    fn javascript_urls() {
        for js in ["javascript:alert(1)", " JaVa\tScRiPt:x", "java\nscript:"] {
            assert!(is_javascript_url(js), "{js:?}");
        }
        assert!(!is_javascript_url("https://x/javascript:"));
    }

    fn lines(html: &str) -> Vec<String> {
        scan_html(html).into_iter().map(|(_, m)| m).collect()
    }

    #[test]
    fn a_clean_page_passes() {
        let page = r#"<!doctype html><html><head><script type="module" src="/theme.js"></script>
            <link rel="stylesheet" href="/site.css"></head>
            <body class=x><a href="https://github.com/Aivyx-Agent/aivyx-pack">ok</a>
            <!-- <script>alert(1)</script> style="x" github.com/Aivyx-Agent/aivyx-hub -->
            <p>a &lt; b, and the online shop</p>
            </body></html>"#;
        assert!(lines(page).is_empty(), "{:?}", lines(page));
    }

    #[test]
    fn inline_scripts_and_styles() {
        let found = lines("<p>\n<SCRIPT type=module>let s = '<style>';</script>");
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("inline <script>"));
        assert_eq!(scan_html("<p>\n\n<script>x</script>")[0].0, 3);
        let found = lines("<script src=\"\">x</script>");
        assert!(found[0].contains("inline <script>"), "{found:?}");
        let found = lines("<script type=\"application/ld+json\">{}</script>");
        assert!(
            found[0].contains("inline data script (type=application/ld+json); serve it as a file"),
            "{found:?}"
        );
        let found = lines("<style>p{}</style>");
        assert!(found[0].contains("<style> element"), "{found:?}");
        let found = lines("<div STYLE='color:red'>");
        assert!(found[0].contains("style=\""), "{found:?}");
    }

    #[test]
    fn event_handlers_and_javascript_urls() {
        let found = lines("<button onClick=\"go()\">");
        assert!(
            found[0].contains("inline event handler onclick="),
            "{found:?}"
        );
        let found = lines("<a href=\"java&#115;cript:go()\">");
        assert!(found[0].contains("href is a javascript: URL"), "{found:?}");
        // Only URL attributes: prose that starts with "JavaScript:" is fine.
        assert!(lines("<meta name=description content=\"JavaScript: tips\">").is_empty());
        let found = lines("<img srcset=\"/a.png 1x, javascript:x 2x\">");
        assert!(
            found[0].contains("srcset is a javascript: URL"),
            "{found:?}"
        );
        // `on` alone and names merely containing it are fine.
        assert!(lines("<x on=\"1\" data-on=\"2\">").is_empty());
    }

    #[test]
    fn private_links_anywhere() {
        let found = lines("<img src=https://github.com/aivyx-agent/aivyx-brand/raw/x.png>");
        assert!(
            found[0].contains("src links the private repo aivyx-brand"),
            "{found:?}"
        );
        let found = lines("<a title='a > b' href=\"https://github.com/Aivyx-Agent/aivyx-hub#x\">");
        assert!(found[0].contains("aivyx-hub"), "{found:?}");
        let found = lines(
            "<a href=\"https&colon;&sol;&sol;github&period;com&#47;Aivyx-Agent&#x2F;aivyx-hub\">",
        );
        assert!(
            found[0].contains("href links the private repo aivyx-hub"),
            "{found:?}"
        );
        let found = lines("<p>\nsee github.com/Aivyx-Agent/aivyx-ecosystem for more</p>");
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("text links the private repo aivyx-ecosystem"));
        assert_eq!(
            scan_html("<p>\nsee github.com/Aivyx-Agent/aivyx-ecosystem")[0].0,
            2
        );
        let found = lines(
            "<script src=/a.js>fetch('https://raw.githubusercontent.com/Aivyx-Agent/aivyx-deploy/x')</script>",
        );
        assert!(
            found[0].contains("<script> body links the private repo aivyx-deploy"),
            "{found:?}"
        );
        let found = lines(
            "<link rel=x href=/a.css><style src=x>a{background:url(//github.com/Aivyx-Agent/aivyx-website/x.png)}</style>",
        );
        assert!(
            found
                .iter()
                .any(|l| l.contains("<style> body links the private repo aivyx-website")),
            "{found:?}"
        );
    }
}
