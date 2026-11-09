//! Read-only, bounded metadata from Debian's standard Nginx configuration tree.
//! No nginx subprocess, request logs, environment expansion or arbitrary includes.
use remi_core::services::{NginxContext, NginxSite};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

const MAX_BYTES: usize = 1024 * 1024;
const MAX_FILES: usize = 96;
const MAX_DEPTH: usize = 32;
const MAX_SITES: usize = 64;

#[derive(Debug)]
struct Directive {
    words: Vec<String>,
    children: Vec<Directive>,
    source: String,
}

#[derive(Debug, PartialEq)]
enum Token {
    Word(String),
    Open,
    Close,
    End,
}

fn tokens(input: &str) -> Result<Vec<Token>, ()> {
    let mut result = Vec::new();
    let mut chars = input.chars().peekable();
    let mut word = String::new();
    let mut started = false;
    let mut quote = None;
    let mut variable = false;
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            word.push(chars.next().ok_or(())?);
            started = true;
            continue;
        }
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else {
                word.push(ch);
            }
            continue;
        }
        if matches!(ch, '\'' | '"') {
            quote = Some(ch);
            started = true;
            continue;
        }
        if ch == '{' && word.ends_with('$') {
            variable = true;
        }
        if variable {
            word.push(ch);
            if ch == '}' {
                variable = false;
            }
            continue;
        }
        if ch.is_whitespace() || matches!(ch, ';' | '{' | '}' | '#') {
            if started {
                result.push(Token::Word(std::mem::take(&mut word)));
                started = false;
            }
            match ch {
                ';' => result.push(Token::End),
                '{' => result.push(Token::Open),
                '}' => result.push(Token::Close),
                '#' => {
                    for c in chars.by_ref() {
                        if c == '\n' {
                            break;
                        }
                    }
                }
                _ => (),
            }
        } else {
            word.push(ch);
            started = true;
        }
        if result.len() > 65_536 || word.len() > 8192 {
            return Err(());
        }
    }
    if quote.is_some() || variable || started {
        return Err(());
    }
    Ok(result)
}

struct Reader {
    root: PathBuf,
    stack: Vec<PathBuf>,
    bytes: usize,
    files: usize,
    partial: bool,
}
impl Reader {
    fn file(&mut self, path: &Path, depth: usize) -> Vec<Directive> {
        match self.try_file(path, depth) {
            Ok(nodes) => nodes,
            Err(()) => {
                tracing::debug!(
                    action = "nginx_context_file_unavailable",
                    depth,
                    files = self.files,
                    bytes = self.bytes
                );
                self.partial = true;
                vec![]
            }
        }
    }
    fn try_file(&mut self, path: &Path, depth: usize) -> Result<Vec<Directive>, ()> {
        if depth > MAX_DEPTH || self.files >= MAX_FILES || self.bytes >= MAX_BYTES {
            return Err(());
        }
        let path = path.canonicalize().map_err(|_| ())?;
        if !path.starts_with(&self.root) || self.stack.contains(&path) {
            return Err(());
        }
        // Nonblocking open also bounds a misconfigured include pointing to a FIFO.
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
        let file = options.open(&path).map_err(|_| ())?;
        if !file.metadata().map_err(|_| ())?.is_file() {
            return Err(());
        }
        let mut input = String::new();
        file.take((MAX_BYTES - self.bytes + 1) as u64)
            .read_to_string(&mut input)
            .map_err(|_| ())?;
        self.files += 1;
        self.bytes += input.len();
        if self.bytes > MAX_BYTES {
            return Err(());
        }
        let tokens = tokens(&input)?;
        let source = path
            .file_name()
            .and_then(|s| s.to_str())
            .filter(|s| safe_name(s))
            .unwrap_or("config")
            .to_owned();
        self.stack.push(path);
        let result = self.block(&tokens, &mut 0, depth, false, &source);
        self.stack.pop();
        result
    }
    fn block(
        &mut self,
        tokens: &[Token],
        cursor: &mut usize,
        depth: usize,
        nested: bool,
        source: &str,
    ) -> Result<Vec<Directive>, ()> {
        if depth > MAX_DEPTH {
            return Err(());
        }
        let mut nodes = Vec::new();
        let mut words = Vec::new();
        while let Some(token) = tokens.get(*cursor) {
            *cursor += 1;
            match token {
                Token::Word(w) => words.push(w.clone()),
                Token::Close if words.is_empty() && nested => return Ok(nodes),
                Token::Close => return Err(()),
                Token::Open | Token::End => {
                    if words.is_empty() {
                        return Err(());
                    }
                    let children = if *token == Token::Open {
                        self.block(tokens, cursor, depth + 1, true, source)?
                    } else {
                        vec![]
                    };
                    if words[0] == "include" && *token == Token::End {
                        if words.len() == 2 {
                            nodes.extend(self.include(&words[1], depth + 1));
                        } else {
                            self.partial = true;
                        }
                    } else {
                        nodes.push(Directive {
                            words: std::mem::take(&mut words),
                            children,
                            source: source.into(),
                        });
                    }
                    words.clear();
                }
            }
        }
        if nested || !words.is_empty() {
            Err(())
        } else {
            Ok(nodes)
        }
    }
    fn include(&mut self, value: &str, depth: usize) -> Vec<Directive> {
        if value.contains(['$', '[', ']']) {
            self.partial = true;
            return vec![];
        }
        let path = self.root.join(value);
        let Some(parent) = path.parent().and_then(|p| p.canonicalize().ok()) else {
            self.partial = true;
            return vec![];
        };
        if !parent.starts_with(&self.root) {
            self.partial = true;
            return vec![];
        }
        let Some(pattern) = path.file_name().and_then(|p| p.to_str()) else {
            self.partial = true;
            return vec![];
        };
        if !pattern.contains(['*', '?']) {
            return self.file(&path, depth);
        }
        let Ok(entries) = fs::read_dir(parent) else {
            self.partial = true;
            return vec![];
        };
        let mut paths = Vec::new();
        for (i, entry) in entries.enumerate() {
            if i >= 512 {
                self.partial = true;
                break;
            }
            match entry {
                Ok(e) if wildcard(pattern.as_bytes(), e.file_name().as_encoded_bytes()) => {
                    paths.push(e.path())
                }
                Err(_) => self.partial = true,
                _ => (),
            }
        }
        paths.sort();
        paths
            .into_iter()
            .flat_map(|p| self.file(&p, depth))
            .collect()
    }
}

// Linear backtracking for filename-only '*' and '?'; never recursively walks directories.
fn wildcard(pattern: &[u8], name: &[u8]) -> bool {
    let (mut p, mut n, mut star, mut retry) = (0, 0, None, 0);
    while n < name.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if pattern.get(p) == Some(&b'*') {
            star = Some(p);
            p += 1;
            retry = n;
        } else if let Some(s) = star {
            retry += 1;
            n = retry;
            p = s + 1;
        } else {
            return false;
        }
    }
    while pattern.get(p) == Some(&b'*') {
        p += 1;
    }
    p == pattern.len()
}

fn safe_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".-_*".contains(&c))
}
fn authority(value: &str) -> Option<String> {
    // Retain only a literal authority. Paths, query strings and userinfo never leave the agent.
    let value = value.split(['/', '?', '#']).next()?;
    if value.is_empty()
        || value.len() > 253
        || value.contains(['@', '$'])
        || value.starts_with("unix:")
    {
        return None;
    }
    value
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || b".-_:[]".contains(&c))
        .then(|| value.to_owned())
}
fn listen_port(value: &str) -> Option<u16> {
    if value.starts_with("unix:") || value.contains('$') {
        return None;
    }
    if let Ok(port) = value.parse::<u16>() {
        return (port > 0).then_some(port);
    }
    value
        .rsplit_once(':')?
        .1
        .parse::<u16>()
        .ok()
        .filter(|p| *p > 0)
}
fn descendants(nodes: &[Directive]) -> impl Iterator<Item = &Directive> {
    // The parser already bounds nesting. Use a small explicit stack for extraction.
    let mut stack: Vec<_> = nodes.iter().rev().collect();
    std::iter::from_fn(move || {
        let node = stack.pop()?;
        stack.extend(node.children.iter().rev());
        Some(node)
    })
}

pub fn inspect(root: &Path, port: u16) -> NginxContext {
    let Ok(root) = root.canonicalize() else {
        return NginxContext {
            partial: true,
            ..Default::default()
        };
    };
    let mut reader = Reader {
        root: root.clone(),
        stack: vec![],
        bytes: 0,
        files: 0,
        partial: false,
    };
    let nodes = reader.file(&root.join("nginx.conf"), 0);
    let mut sites = Vec::new();
    for http in nodes.iter().filter(|n| n.words[0] == "http") {
        let mut upstreams = BTreeMap::new();
        for node in http
            .children
            .iter()
            .filter(|n| n.words[0] == "upstream" && n.words.len() == 2)
        {
            let mut destinations = Vec::new();
            for server in node.children.iter().filter(|n| n.words[0] == "server") {
                if let Some(address) = server.words.get(1).and_then(|s| authority(s)) {
                    destinations.push(address);
                } else {
                    reader.partial = true;
                }
            }
            upstreams.insert(node.words[1].as_str(), destinations);
        }
        for server in http.children.iter().filter(|n| n.words[0] == "server") {
            let listeners: Vec<_> = server
                .children
                .iter()
                .filter(|n| n.words[0] == "listen")
                .collect();
            if listeners
                .iter()
                .any(|n| n.words.get(1).and_then(|s| listen_port(s)).is_none())
            {
                reader.partial = true;
            }
            if listeners.is_empty() {
                reader.partial = true;
            }
            let matching: Vec<_> = listeners
                .iter()
                .filter(|n| n.words.get(1).and_then(|s| listen_port(s)) == Some(port))
                .collect();
            if matching.is_empty() {
                continue;
            }
            if sites.len() >= MAX_SITES {
                reader.partial = true;
                break;
            }
            let mut site = NginxSite {
                source: server.source.clone(),
                names: vec![],
                tls: matching.iter().any(|n| n.words.iter().any(|s| s == "ssl")),
                backends: vec![],
            };
            for name in server
                .children
                .iter()
                .filter(|n| n.words[0] == "server_name")
                .flat_map(|n| &n.words[1..])
            {
                if safe_name(name) {
                    site.names.push(name.clone());
                } else {
                    reader.partial = true;
                }
            }
            for node in descendants(&server.children).filter(|n| n.words[0] == "proxy_pass") {
                let Some((scheme, address)) = node
                    .words
                    .get(1)
                    .and_then(|v| v.split_once("://"))
                    .filter(|(s, _)| matches!(*s, "http" | "https"))
                else {
                    reader.partial = true;
                    continue;
                };
                let Some(address) = authority(address) else {
                    reader.partial = true;
                    continue;
                };
                if let Some(destinations) = upstreams.get(address.as_str()) {
                    if destinations.is_empty() {
                        reader.partial = true;
                    }
                    for destination in destinations {
                        site.backends.push(format!("{scheme}://{destination}"));
                    }
                } else {
                    site.backends.push(format!("{scheme}://{address}"));
                }
            }
            for values in [&mut site.names, &mut site.backends] {
                values.sort();
                values.dedup();
                if values.len() > 16 {
                    reader.partial = true;
                    values.truncate(16);
                }
            }
            sites.push(site);
        }
    }
    sites.sort_by(|a, b| (&a.source, &a.names).cmp(&(&b.source, &b.names)));
    // Reserve most of the protocol frame for sockets; never let metadata crowd it out.
    let mut encoded_bytes = 0;
    sites.retain(|site| {
        encoded_bytes += serde_json::to_vec(site).map_or(65_537, |v| v.len());
        if encoded_bytes > 65_536 {
            reader.partial = true;
            false
        } else {
            true
        }
    });
    let result = NginxContext {
        sites,
        files_read: reader.files,
        partial: reader.partial,
    };
    tracing::info!(
        action = "nginx_context_read",
        port,
        files = result.files_read,
        sites = result.sites.len(),
        partial = result.partial,
        bytes = reader.bytes
    );
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn write(root: &Path, file: &str, contents: &str) {
        fs::write(root.join(file), contents).unwrap();
    }

    #[test]
    fn catalog_matches_port_resolves_includes_and_redacts_request_material() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "nginx.conf",
            "events {} http { upstream api { server 127.0.0.1:8000; server [::1]:8001; } include *.site; }",
        );
        write(
            root,
            "one.site",
            r#"server {
            listen 443 ssl; listen [::]:443 ssl; server_name app.example.test *.example.test;
            location / { proxy_pass http://api/private?token=DO_NOT_EXPORT; }
            include nested.inc;
            proxy_set_header Authorization "Bearer DO_NOT_EXPORT";
            set $unused "a; { # }"; set $other ${host};
        }
        server { listen 80; server_name other.example.test; proxy_pass http://127.0.0.1:9000; }"#,
        );
        write(
            root,
            "nested.inc",
            "location /second { proxy_pass https://backend.example.test/secret; }",
        );
        let result = inspect(root, 443);
        assert!(!result.partial);
        assert_eq!(result.files_read, 3);
        assert_eq!(result.sites.len(), 1);
        let site = &result.sites[0];
        assert_eq!(site.source, "one.site");
        assert!(site.tls);
        assert_eq!(site.names, ["*.example.test", "app.example.test"]);
        assert_eq!(
            site.backends,
            [
                "http://127.0.0.1:8000",
                "http://[::1]:8001",
                "https://backend.example.test"
            ]
        );
        let serialized = serde_json::to_string(&result).unwrap();
        for forbidden in [
            "DO_NOT_EXPORT",
            "private",
            "secret",
            "Authorization",
            "9000",
            "other.example",
        ] {
            assert!(!serialized.contains(forbidden), "leaked {forbidden}");
        }
        let other = inspect(root, 80);
        assert_eq!(other.sites.len(), 1);
        assert!(!other.sites[0].tls);
        assert_eq!(other.sites[0].backends, ["http://127.0.0.1:9000"]);
        assert!(inspect(root, 22).sites.is_empty());
    }

    #[test]
    fn unavailable_dynamic_and_malformed_inputs_are_partial_without_losing_valid_sites() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        assert!(inspect(root, 443).partial);
        for bad in [
            "include missing.conf;",
            "include nginx.conf;",
            "include /outside/tree.conf;",
            "include bad.inc;",
            "server { listen 443; proxy_pass http://$dynamic; }",
            "server { listen 443; proxy_pass http://user:password@host/path; }",
        ] {
            write(
                root,
                "nginx.conf",
                &format!("http {{ server {{ listen 443 ssl; server_name good.test; }} {bad} }}"),
            );
            write(root, "bad.inc", "server { listen 443;");
            let result = inspect(root, 443);
            assert!(result.partial, "{bad}");
            assert!(result.sites.iter().any(|s| s.names == ["good.test"]));
            let output = serde_json::to_string(&result).unwrap();
            assert!(!output.contains("password"));
            assert!(!output.contains("dynamic"));
        }
        write(
            root,
            "nginx.conf",
            "http { server { listen 443; server_name recovered.test; } }",
        );
        let result = inspect(root, 443);
        assert!(!result.partial);
        assert_eq!(result.sites[0].names, ["recovered.test"]);
    }

    #[test]
    fn bounds_and_symlinks_cannot_escape_the_configuration_tree() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            outside.path(),
            "private",
            "http { server { listen 443; server_name leaked.test; } }",
        );
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path().join("private"), root.join("escape")).unwrap();
        write(root, "nginx.conf", "include escape;");
        let result = inspect(root, 443);
        assert!(result.partial);
        assert!(result.sites.is_empty());
        write(root, "nginx.conf", &" ".repeat(MAX_BYTES + 1));
        assert!(inspect(root, 443).partial);
        write(
            root,
            "nginx.conf",
            &format!(
                "{}{}",
                "http { ".repeat(MAX_DEPTH + 1),
                "}".repeat(MAX_DEPTH + 1)
            ),
        );
        assert!(inspect(root, 443).partial);
        write(
            root,
            "nginx.conf",
            &format!(
                "http {{ {} }}",
                "server { listen 443; }".repeat(MAX_SITES + 1)
            ),
        );
        let result = inspect(root, 443);
        assert!(result.partial);
        assert_eq!(result.sites.len(), MAX_SITES);
    }
}
