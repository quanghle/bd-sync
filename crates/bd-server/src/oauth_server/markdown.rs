//! The approval packet's Markdown (`pages::approve_gate`): workspace-authored
//! text, untrusted, rendered to HTML by an emitter of its own over the
//! parser's events, never `pulldown_cmark::html::push_html`. Only the
//! constructs below are written as markup; everything else is text:
//!
//! - headings (demoted to `h4`–`h6`, below the page's own), paragraphs,
//!   lists, block quotes, rules, emphasis, strong, strikethrough, inline and
//!   block code (a fence's info string dropped), tables (in a scrolling
//!   `div.md-table`) and task list markers (disabled checkboxes);
//! - raw HTML, block and inline, shown as escaped code;
//! - images as their alt text, never fetched;
//! - links active only to an absolute http(s) URL (a new tab, no referrer)
//!   or a fragment on the page itself (no target, so it never reloads the
//!   page's one-time URL); any other destination is shown, inert.
//!
//! Control, direction and invisible characters are shown as `\uXXXX`, as
//! `pages` shows titles; newlines and tabs keep their meaning.
use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, LinkType, Options, Parser, Tag, TagEnd};

use super::clients::hidden;
use super::pages::escape;

/// The longest link destination made active.
const MAX_HREF: usize = 2048;
/// How much of an inert link's destination is shown, in characters.
const MAX_INERT_SHOWN: usize = 200;

/// `source` as HTML, or None if the HTML would be longer than `max` bytes:
/// a fragment is whole or not at all, never cut.
pub fn render(source: &str, max: usize) -> Option<String> {
    let options = Options::ENABLE_TABLES | Options::ENABLE_TASKLISTS | Options::ENABLE_STRIKETHROUGH;
    let mut out = String::new();
    // The links open, innermost last, and how each one ends.
    let mut links: Vec<Dest> = Vec::new();
    // How deep inside images: their content is alt text only.
    let mut image = 0usize;
    let mut table_head = false;
    let mut table_body = false;
    let mut html_block = false;
    for event in Parser::new_ext(source, options) {
        if image > 0 {
            match event {
                Event::Start(Tag::Image { .. }) => image += 1,
                Event::End(TagEnd::Image) => {
                    image -= 1;
                    if image == 0 {
                        out.push_str("]</span>");
                    }
                }
                Event::Text(text) | Event::Code(text) => visible(&text, &mut out),
                _ => {}
            }
        } else {
            match event {
                Event::Start(tag) => match tag {
                    Tag::Paragraph => out.push_str("<p>"),
                    Tag::Heading { level, id: _, classes: _, attrs: _ } => {
                        out.push_str(&format!("<h{}>", demoted(level)));
                    }
                    Tag::BlockQuote(_) => out.push_str("<blockquote>\n"),
                    Tag::CodeBlock(CodeBlockKind::Indented | CodeBlockKind::Fenced(_)) => {
                        out.push_str("<pre><code>");
                    }
                    Tag::HtmlBlock => {
                        html_block = true;
                        out.push_str("<pre class=\"md-raw\"><code>");
                    }
                    Tag::List(None) => out.push_str("<ul>\n"),
                    Tag::List(Some(1)) => out.push_str("<ol>\n"),
                    Tag::List(Some(start)) => out.push_str(&format!("<ol start=\"{start}\">\n")),
                    Tag::Item => out.push_str("<li>"),
                    Tag::Table(_) => {
                        table_head = false;
                        table_body = false;
                        out.push_str("<div class=\"md-table\"><table>");
                    }
                    Tag::TableHead => {
                        table_head = true;
                        out.push_str("<thead><tr>");
                    }
                    Tag::TableRow => out.push_str("<tr>"),
                    Tag::TableCell => out.push_str(if table_head { "<th>" } else { "<td>" }),
                    Tag::Emphasis => out.push_str("<em>"),
                    Tag::Strong => out.push_str("<strong>"),
                    Tag::Strikethrough => out.push_str("<del>"),
                    Tag::Link { link_type, dest_url, title: _, id: _ } => {
                        let dest = classify(&dest_url, matches!(link_type, LinkType::Autolink | LinkType::Email));
                        match &dest {
                            Dest::Fragment(href) => out.push_str(&format!("<a href=\"{}\">", escape(href))),
                            Dest::Web { href, .. } => out.push_str(&format!(
                                "<a href=\"{}\" target=\"_blank\" rel=\"noopener noreferrer nofollow\" \
                                 referrerpolicy=\"no-referrer\">",
                                escape(href)
                            )),
                            Dest::Inert(_) => {}
                        }
                        links.push(dest);
                    }
                    Tag::Image { link_type: _, dest_url: _, title: _, id: _ } => {
                        image = 1;
                        out.push_str("<span class=\"md-image\">[image: ");
                    }
                    // Not enabled: their content is shown as it comes.
                    Tag::FootnoteDefinition(_)
                    | Tag::DefinitionList
                    | Tag::DefinitionListTitle
                    | Tag::DefinitionListDefinition
                    | Tag::Superscript
                    | Tag::Subscript
                    | Tag::MetadataBlock(_) => {}
                },
                Event::End(end) => match end {
                    TagEnd::Paragraph => out.push_str("</p>\n"),
                    TagEnd::Heading(level) => out.push_str(&format!("</h{}>\n", demoted(level))),
                    TagEnd::BlockQuote(_) => out.push_str("</blockquote>\n"),
                    TagEnd::CodeBlock => out.push_str("</code></pre>\n"),
                    TagEnd::HtmlBlock => {
                        html_block = false;
                        out.push_str("</code></pre>\n");
                    }
                    TagEnd::List(true) => out.push_str("</ol>\n"),
                    TagEnd::List(false) => out.push_str("</ul>\n"),
                    TagEnd::Item => out.push_str("</li>\n"),
                    TagEnd::Table => {
                        if table_body {
                            out.push_str("</tbody>");
                        }
                        out.push_str("</table></div>\n");
                    }
                    TagEnd::TableHead => {
                        table_head = false;
                        table_body = true;
                        out.push_str("</tr></thead><tbody>\n");
                    }
                    TagEnd::TableRow => out.push_str("</tr>\n"),
                    TagEnd::TableCell => out.push_str(if table_head { "</th>" } else { "</td>" }),
                    TagEnd::Emphasis => out.push_str("</em>"),
                    TagEnd::Strong => out.push_str("</strong>"),
                    TagEnd::Strikethrough => out.push_str("</del>"),
                    TagEnd::Link => match links.pop() {
                        Some(Dest::Fragment(_)) => out.push_str("</a>"),
                        Some(Dest::Web { href, autolink }) => {
                            out.push_str("</a>");
                            if !autolink {
                                out.push_str(" <span class=\"md-dest\">(");
                                visible(&href, &mut out);
                                out.push_str(")</span>");
                            }
                        }
                        Some(Dest::Inert(dest)) => {
                            out.push_str(" <span class=\"md-inert\">(link not active: <code>");
                            let shown: String = if dest.chars().count() > MAX_INERT_SHOWN {
                                dest.chars().take(MAX_INERT_SHOWN).chain(std::iter::once('…')).collect()
                            } else {
                                dest
                            };
                            visible(&shown, &mut out);
                            out.push_str("</code>)</span>");
                        }
                        None => {}
                    },
                    // Images end above; the rest are not enabled.
                    TagEnd::Image
                    | TagEnd::FootnoteDefinition
                    | TagEnd::DefinitionList
                    | TagEnd::DefinitionListTitle
                    | TagEnd::DefinitionListDefinition
                    | TagEnd::Superscript
                    | TagEnd::Subscript
                    | TagEnd::MetadataBlock(_) => {}
                },
                Event::Text(text) => visible(&text, &mut out),
                Event::Code(code) => {
                    out.push_str("<code>");
                    visible(&code, &mut out);
                    out.push_str("</code>");
                }
                Event::Html(html) if html_block => visible(&html, &mut out),
                Event::Html(html) | Event::InlineHtml(html) => {
                    out.push_str("<code class=\"md-raw\">");
                    visible(&html, &mut out);
                    out.push_str("</code>");
                }
                Event::SoftBreak => out.push('\n'),
                Event::HardBreak => out.push_str("<br>\n"),
                Event::Rule => out.push_str("<hr>\n"),
                Event::TaskListMarker(done) => {
                    out.push_str(if done {
                        "<input type=\"checkbox\" disabled checked> "
                    } else {
                        "<input type=\"checkbox\" disabled> "
                    });
                }
                // Not enabled: shown as the text they came from.
                Event::FootnoteReference(name) => visible(&format!("[^{name}]"), &mut out),
                Event::InlineMath(math) => visible(&format!("${math}$"), &mut out),
                Event::DisplayMath(math) => visible(&format!("$${math}$$"), &mut out),
            }
        }
        if out.len() > max {
            return None;
        }
    }
    Some(out)
}

/// An authored heading's level on the page: three below, so it never
/// outranks the page's own `h1`–`h3`.
fn demoted(level: HeadingLevel) -> usize {
    (level as usize + 3).min(6)
}

/// Where a link goes, and so how it is written.
#[derive(Debug, PartialEq, Eq)]
enum Dest {
    /// A fragment of this page: `#` and a name.
    Fragment(String),
    /// An absolute http(s) URL; `autolink` when its text is the URL itself.
    Web { href: String, autolink: bool },
    /// Anything else, shown but not followed.
    Inert(String),
}

/// How a link to `dest` (as the parser decoded it: entities and escapes
/// already resolved) is written.
fn classify(dest: &str, autolink: bool) -> Dest {
    let plain = |c: char| !c.is_whitespace() && !c.is_control() && !hidden(c);
    if let Some(name) = dest.strip_prefix('#') {
        if !name.is_empty() && name.chars().all(plain) {
            return Dest::Fragment(dest.to_string());
        }
        return Dest::Inert(dest.to_string());
    }
    let lower = dest.get(..8).unwrap_or(dest).to_ascii_lowercase();
    let rest = if lower.starts_with("https://") {
        &dest[8..]
    } else if lower.starts_with("http://") {
        &dest[7..]
    } else {
        return Dest::Inert(dest.to_string());
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    let host = host.split(':').next().unwrap_or("");
    let safe = |c: char| plain(c) && !matches!(c, '\\' | '<' | '>' | '"' | '`');
    if dest.len() <= MAX_HREF && !host.is_empty() && dest.chars().all(safe) {
        Dest::Web { href: dest.to_string(), autolink }
    } else {
        Dest::Inert(dest.to_string())
    }
}

/// Appends `text` to `out` as HTML text: newlines and tabs kept (a CRLF
/// folded to a newline), any other control, direction or invisible
/// character as `\uXXXX`.
fn visible(text: &str, out: &mut String) {
    let mut plain = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' | '\t' => plain.push(c),
            c if c.is_control() || hidden(c) => plain.push_str(&format!("\\u{:04x}", c as u32)),
            c => plain.push(c),
        }
    }
    out.push_str(&escape(&plain));
}

/// Whether `html`'s tags nest: each one opened is closed, in order (void
/// elements: `input`, `br`, `hr`), and every `<` starts a tag.
#[cfg(test)]
pub(crate) fn balanced(html: &str) -> bool {
    let mut open: Vec<&str> = Vec::new();
    let mut rest = html;
    while let Some(at) = rest.find('<') {
        rest = &rest[at + 1..];
        let Some(end) = rest.find('>') else { return false };
        let tag = &rest[..end];
        rest = &rest[end + 1..];
        if let Some(name) = tag.strip_prefix('/') {
            if open.pop() != Some(name) {
                return false;
            }
            continue;
        }
        let name = tag.split([' ', '\n']).next().unwrap_or("");
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric()) {
            return false;
        }
        if !matches!(name, "input" | "br" | "hr") {
            open.push(name);
        }
    }
    open.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn html(source: &str) -> String {
        let out = render(source, usize::MAX).unwrap();
        assert!(balanced(&out), "unbalanced: {out}");
        out
    }

    /// The tags in `html`, each the text between its `<` and `>`.
    fn tags(html: &str) -> Vec<&str> {
        let mut tags = Vec::new();
        let mut rest = html;
        while let Some(at) = rest.find('<') {
            rest = &rest[at + 1..];
            let end = rest.find('>').unwrap();
            tags.push(&rest[..end]);
            rest = &rest[end + 1..];
        }
        tags
    }

    /// The `href` values in `html`.
    fn hrefs(html: &str) -> Vec<String> {
        html.split("href=\"").skip(1).map(|s| s[..s.find('"').unwrap()].to_string()).collect()
    }

    /// Asserts that every link in `html` goes to a fragment or a validated http(s) URL.
    fn only_safe_links(html: &str) {
        for href in hrefs(html) {
            let ok = matches!(classify(&href.replace("&amp;", "&"), false), Dest::Fragment(_) | Dest::Web { .. });
            assert!(ok, "unsafe href {href:?} in {html}");
        }
        for tag in tags(html) {
            assert!(!tag.to_ascii_lowercase().contains(" on"), "event handler in <{tag}>");
            assert!(!tag.contains("src="), "src in <{tag}>");
        }
    }

    #[test]
    fn markdown_maps_to_its_own_markup() {
        let out = html(
            "# Title\n\n## Sub\n\n###### Six\n\nSome *em*, **strong** and ~~gone~~ text with `code`.\n\n\
             - one\n- two\n\ntext\n\n3. three\n4. four\n\ntext\n\n1. first\n\n> quoted\n\n---\n\n\
             ```rust\nfn main() {}\n```\n\n    indented\n\n\
             | a | b |\n|:--|--:|\n| 1 | 2 |\n\n- [x] done\n- [ ] todo\n\nline  \nbreak\n",
        );
        assert!(out.contains("<h4>Title</h4>"), "{out}");
        assert!(out.contains("<h5>Sub</h5>"));
        assert!(out.contains("<h6>Six</h6>"));
        assert!(!out.contains("<h1") && !out.contains("<h2") && !out.contains("<h3"));
        assert!(
            out.contains("<em>em</em>") && out.contains("<strong>strong</strong>") && out.contains("<del>gone</del>")
        );
        assert!(out.contains("<code>code</code>"));
        assert!(out.contains("<ul>\n<li>one</li>"));
        assert!(out.contains("<ol start=\"3\">\n<li>three</li>"));
        assert!(out.contains("<ol>\n<li>first</li>"));
        assert!(out.contains("<blockquote>\n<p>quoted</p>\n</blockquote>"));
        assert!(out.contains("<hr>"));
        assert!(out.contains("<pre><code>fn main() {}\n</code></pre>"));
        assert!(out.contains("<pre><code>indented\n</code></pre>"));
        assert!(!out.contains("class=\"language"));
        assert!(out.contains(
            "<div class=\"md-table\"><table><thead><tr><th>a</th><th>b</th></tr></thead><tbody>\n\
             <tr><td>1</td><td>2</td></tr>\n</tbody></table></div>"
        ));
        assert!(!out.contains("align") && !out.contains("style"));
        assert!(out.contains("<li><input type=\"checkbox\" disabled checked> done</li>"));
        assert!(out.contains("<li><input type=\"checkbox\" disabled> todo</li>"));
        assert!(out.contains("line<br>\nbreak"));
        for tag in tags(&out).into_iter().filter(|t| t.starts_with("input")) {
            assert!(!tag.contains("name") && !tag.contains("id=") && !tag.contains("form") && !tag.contains("value"));
        }
    }

    #[test]
    fn raw_html_is_shown_as_text() {
        let hostile = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<form action=//evil><button>Approve</button></form>",
        ];
        for raw in hostile {
            for source in [format!("{raw}\n"), format!("before {raw} after\n"), format!("- item\n\n  {raw}\n")] {
                let out = html(&source);
                assert!(out.contains("&lt;"), "{out}");
                for tag in ["<script", "<form", "<button", "<img"] {
                    assert!(!out.contains(tag), "{tag} in {out}");
                }
                assert!(out.contains("class=\"md-raw\""), "{out}");
                only_safe_links(&out);
            }
        }
        let out = html("<script>alert(1)</script>\n");
        assert_eq!(out, "<pre class=\"md-raw\"><code>&lt;script&gt;alert(1)&lt;/script&gt;\n</code></pre>\n");
        let out = html("a <b onclick=x>bold</b>");
        assert!(
            out.contains(
                "<code class=\"md-raw\">&lt;b onclick=x&gt;</code>bold<code class=\"md-raw\">&lt;/b&gt;</code>"
            )
        );
    }

    #[test]
    fn images_are_their_alt_text() {
        for source in [
            "![PIXEL](https://evil.example/p.png)",
            "![PIXEL *em* `code` [l](https://x.example)](https://evil.example/p.png \"t\")",
            "[![PIXEL](https://evil.example/p.png)](https://ok.example/)",
            "![PIXEL][r]\n\n[r]: https://evil.example/p.png",
            "![a ![PIXEL](x.png) b](y.png)",
        ] {
            let out = html(source);
            assert!(out.contains("<span class=\"md-image\">[image: "), "{out}");
            assert!(out.contains("PIXEL"), "{out}");
            assert!(!out.contains("<img") && !out.contains("src=") && !out.contains("p.png\""), "{out}");
            assert!(!out.contains("evil.example"), "{out}");
            only_safe_links(&out);
        }
        assert_eq!(
            html("![PIXEL *em* `code`](https://evil.example/p.png)"),
            "<p><span class=\"md-image\">[image: PIXEL em code]</span></p>\n"
        );
    }

    #[test]
    fn only_web_and_fragment_links_are_active() {
        let inert = [
            "[x](javascript:alert(1))",
            "[x](JaVaScRiPt:alert(1))",
            "[x](&#106;avascript:alert(1))",
            "[x](&#x6A;avascript&colon;alert(1))",
            "[x](java&#x09;script:alert(1))",
            "[x](%6Aavascript:alert(1))",
            "[x](<java\tscript:alert(1)>)",
            "[x](java\u{1}script:alert(1))",
            "[x](<java\nscript:alert(1)>)",
            "[x](data:text/html,<script>alert(1)</script>)",
            "[x](vbscript:msgbox(1))",
            "[x](file:///etc/passwd)",
            "[x](mailto:a@example.com)",
            "[x](//evil.example/)",
            "[x](http:/x)",
            "[x](https://)",
            "[x](https:///path)",
            "[x](https://@/)",
            "[x](relative/path)",
            "[x](/absolute)",
            "[x](?q=1)",
            "[x]()",
            "[x](<https://exa mple.com>)",
            "[x](https://ex\\ample.com)",
            "[x](https://ex\u{202e}ample.com)",
            "[x](https://ex\u{200b}ample.com)",
            "[x](https://ex`ample.com)",
            "[x](#a\u{202e}b)",
            "[x](<#a b>)",
            "[x](#)",
            "<javascript:alert(1)>",
            "<a@example.com>",
            "[x][r]\n\n[r]: javascript:alert(1)",
        ];
        for source in inert {
            let out = html(source);
            assert!(hrefs(&out).is_empty(), "{source:?} gave a link: {out}");
            assert!(!out.contains("<a "), "{source:?}: {out}");
            only_safe_links(&out);
        }
        let out = html("[x](javascript:alert(1))");
        assert_eq!(
            out,
            "<p>x <span class=\"md-inert\">(link not active: <code>javascript:alert(1)</code>)</span></p>\n"
        );
        let out = html(&format!("[x](https://example.com/{})", "a".repeat(MAX_HREF)));
        assert!(!out.contains("<a "), "{out}");
        assert!(out.contains("…</code>)"), "an inert destination is cut: {out}");
        let out = html("[x](<https://ex\u{202e}ample.com>)");
        assert!(out.contains("\\u202e"), "{out}");
    }

    #[test]
    fn web_links_open_apart_and_fragments_in_place() {
        let attrs = "target=\"_blank\" rel=\"noopener noreferrer nofollow\" referrerpolicy=\"no-referrer\"";
        assert_eq!(
            html("[docs](https://example.com/a?b=1&c=2#d \"title\")"),
            format!(
                "<p><a href=\"https://example.com/a?b=1&amp;c=2#d\" {attrs}>docs</a> \
                 <span class=\"md-dest\">(https://example.com/a?b=1&amp;c=2#d)</span></p>\n"
            )
        );
        assert_eq!(
            html("<HTTP://example.com/>"),
            format!("<p><a href=\"HTTP://example.com/\" {attrs}>HTTP://example.com/</a></p>\n")
        );
        assert_eq!(html("[top](#packet-h)"), "<p><a href=\"#packet-h\">top</a></p>\n");
        assert_eq!(
            html("[x][r]\n\n[r]: http://user@example.com:8080/"),
            format!(
                "<p><a href=\"http://user@example.com:8080/\" {attrs}>x</a> \
                 <span class=\"md-dest\">(http://user@example.com:8080/)</span></p>\n"
            )
        );
        assert!(!html("[docs](https://example.com)").contains("title"));
    }

    #[test]
    fn code_fence_info_strings_are_dropped() {
        for info in ["\"><script>", "x onload=alert(1)", "rust class=\"x\""] {
            let out = html(&format!("```{info}\ncode\n```\n"));
            assert_eq!(out, "<pre><code>code\n</code></pre>\n", "{info}");
        }
    }

    #[test]
    fn hidden_characters_are_shown_and_whitespace_kept() {
        let out = html("a\u{202e}b\u{200b}c\u{1b}[31md\u{feff}");
        assert_eq!(out, "<p>a\\u202eb\\u200bc\\u001b[31md\\ufeff</p>\n");
        let out = html("```\n\tx\u{202e}\n\ty\r\n\u{0}\n```\n");
        assert_eq!(out, "<pre><code>\tx\\u202e\n\ty\n\\u0000\n</code></pre>\n");
        let out = html("`a\u{7}b`");
        assert!(out.contains("<code>a\\u0007b</code>"), "{out}");
        let out = html("héllo — 日本語 🙂");
        assert_eq!(out, "<p>héllo — 日本語 🙂</p>\n");
        let out = html("a\u{a0}b\u{3000}c\u{b}d");
        assert_eq!(out, "<p>a\\u00a0b\\u3000c\\u000bd</p>\n");
        let out = html("x & y < z > \"q\" 'r'");
        assert_eq!(out, "<p>x &amp; y &lt; z &gt; &quot;q&quot; &#39;r&#39;</p>\n");
    }

    #[test]
    fn a_fragment_too_long_is_not_rendered() {
        let big = "word ".repeat(10_000);
        assert!(render(&big, 1000).is_none());
        let small = render("hi", usize::MAX).unwrap();
        assert_eq!(render("hi", small.len()), Some(small.clone()));
        assert_eq!(render("hi", small.len() - 1), None);
        let table = format!("| a |\n|---|\n{}", "| x |\n".repeat(1000));
        assert!(render(&table, 500).is_none());
    }

    #[test]
    fn deep_nesting_ends_quickly_and_balanced() {
        let started = std::time::Instant::now();
        for source in [
            format!("{}deep", "> ".repeat(10_000)),
            format!("{}deep", "- ".repeat(10_000)),
            format!("{}deep", "1. ".repeat(10_000)),
            (0..2_000).map(|i| format!("{}- x\n", "  ".repeat(i))).collect(),
            format!("{}x{}", "*".repeat(10_000), "*".repeat(10_000)),
            format!("{}x{}", "[".repeat(10_000), "](#a)".repeat(10_000)),
            format!("{}x{}", "![".repeat(5_000), "](a.png)".repeat(5_000)),
        ] {
            let out = html(&source);
            only_safe_links(&out);
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(20), "took {:?}", started.elapsed());
    }

    #[test]
    fn the_balance_check_finds_stray_tags() {
        assert!(balanced("<p>a<br>b<input type=\"checkbox\" disabled><hr></p>"));
        assert!(!balanced("<p><em>a</p></em>"));
        assert!(!balanced("<p>"));
        assert!(!balanced("</p>"));
        assert!(!balanced("a < b"));
        assert!(!balanced("<p"));
    }
}
