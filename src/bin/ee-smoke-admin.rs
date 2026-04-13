use serde_json::{json, Value};
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::time::Duration;

const DEFAULT_HOST: &str = "0.0.0.0";
const DEFAULT_PORT: u16 = 8080;
const DEFAULT_SOCKET_PATH: &str = "/var/lib/easyenclave/agent.sock";
const DEFAULT_TITLE: &str = "EasyEnclave Smoke Admin";

#[derive(Clone, Debug, PartialEq, Eq)]
struct Config {
    host: String,
    port: u16,
    socket_path: String,
    title: String,
}

#[derive(Debug, PartialEq, Eq)]
struct RequestLine {
    method: String,
    path: String,
}

fn main() {
    let config = Config::from_env();
    let addr = format!("{}:{}", config.host, config.port);

    let listener = TcpListener::bind(&addr).unwrap_or_else(|e| {
        eprintln!("ee-smoke-admin: bind failed on {addr}: {e}");
        std::process::exit(1);
    });
    eprintln!("ee-smoke-admin: listening on http://{addr}");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let config = config.clone();
                std::thread::spawn(move || {
                    if let Err(err) = handle_connection(stream, &config) {
                        eprintln!("ee-smoke-admin: request error: {err}");
                    }
                });
            }
            Err(err) => eprintln!("ee-smoke-admin: accept failed: {err}"),
        }
    }
}

impl Config {
    fn from_env() -> Self {
        Self {
            host: env::var("EE_SMOKE_ADMIN_HOST").unwrap_or_else(|_| DEFAULT_HOST.to_string()),
            port: env::var("EE_SMOKE_ADMIN_PORT")
                .ok()
                .and_then(|raw| raw.parse().ok())
                .unwrap_or(DEFAULT_PORT),
            socket_path: env::var("EE_SOCKET_PATH")
                .unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string()),
            title: env::var("EE_SMOKE_ADMIN_TITLE").unwrap_or_else(|_| DEFAULT_TITLE.to_string()),
        }
    }
}

fn handle_connection(mut stream: TcpStream, config: &Config) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("set read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("set write timeout: {e}"))?;

    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|e| format!("clone stream: {e}"))?,
    );
    let mut request_line = String::new();
    let bytes = reader
        .read_line(&mut request_line)
        .map_err(|e| format!("read request line: {e}"))?;
    if bytes == 0 || request_line.trim().is_empty() {
        return Ok(());
    }

    loop {
        let mut header = String::new();
        let bytes = reader
            .read_line(&mut header)
            .map_err(|e| format!("read header: {e}"))?;
        if bytes == 0 || header == "\r\n" {
            break;
        }
    }

    let request = parse_request_line(&request_line)?;
    let response = route_request(&request, config);
    stream
        .write_all(response.as_bytes())
        .map_err(|e| format!("write response: {e}"))?;
    Ok(())
}

fn parse_request_line(raw: &str) -> Result<RequestLine, String> {
    let mut parts = raw.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "missing method".to_string())?
        .to_string();
    let target = parts.next().ok_or_else(|| "missing path".to_string())?;
    let _version = parts.next().ok_or_else(|| "missing version".to_string())?;
    if parts.next().is_some() {
        return Err("malformed request line".into());
    }

    Ok(RequestLine {
        method,
        path: target.split('?').next().unwrap_or(target).to_string(),
    })
}

fn route_request(request: &RequestLine, config: &Config) -> String {
    if request.method != "GET" {
        return text_response(405, "method not allowed\n");
    }

    match request.path.as_str() {
        "/" => root_response(config),
        "/health" => health_response(config),
        "/deployments" => deployments_response(config),
        _ => text_response(404, "not found\n"),
    }
}

fn root_response(config: &Config) -> String {
    let health = match ee_ok_response(&config.socket_path, json!({"method": "health"})) {
        Ok(value) => value,
        Err(err) => {
            return html_response(
                503,
                &format!(
                    "<!doctype html><title>{}</title><h1>{}</h1><p>easyenclave unavailable: {}</p>",
                    escape_html(&config.title),
                    escape_html(&config.title),
                    escape_html(&err),
                ),
            )
        }
    };

    let deployments = match ee_ok_response(&config.socket_path, json!({"method": "list"})) {
        Ok(value) => value,
        Err(err) => {
            return html_response(
                503,
                &format!(
                    "<!doctype html><title>{}</title><h1>{}</h1><p>deployment query failed: {}</p>",
                    escape_html(&config.title),
                    escape_html(&config.title),
                    escape_html(&err),
                ),
            )
        }
    };

    let health_pretty =
        serde_json::to_string_pretty(&health).unwrap_or_else(|_| "{\"ok\":false}".to_string());

    let rows = deployments["deployments"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|deployment| {
                    let app_name = deployment["app_name"].as_str().unwrap_or("unknown");
                    let status = deployment["status"].as_str().unwrap_or("unknown");
                    let image = deployment["image"].as_str().unwrap_or("");
                    format!(
                        "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                        escape_html(app_name),
                        escape_html(status),
                        escape_html(image),
                    )
                })
                .collect::<String>()
        })
        .filter(|rows| !rows.is_empty())
        .unwrap_or_else(|| {
            "<tr><td colspan=\"3\">No deployments reported by easyenclave</td></tr>".to_string()
        });

    let body = format!(
        concat!(
            "<!doctype html><html><head><meta charset=\"utf-8\">",
            "<title>{title}</title>",
            "<style>",
            "body{{font-family:ui-sans-serif,system-ui,sans-serif;max-width:920px;margin:2rem auto;padding:0 1rem;color:#172033;}}",
            "h1{{margin-bottom:.25rem;}}",
            ".sub{{color:#4b5563;margin-bottom:1.5rem;}}",
            ".grid{{display:grid;gap:1rem;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));}}",
            ".card{{border:1px solid #d6deeb;border-radius:12px;padding:1rem;background:#fbfcfe;}}",
            "pre{{white-space:pre-wrap;word-break:break-word;margin:0;}}",
            "table{{width:100%;border-collapse:collapse;}}",
            "th,td{{padding:.6rem;border-bottom:1px solid #e5e7eb;text-align:left;vertical-align:top;}}",
            "</style></head><body>",
            "<h1>{title}</h1>",
            "<div class=\"sub\">Public native smoke-admin for EasyEnclave integration tests</div>",
            "<div class=\"grid\">",
            "<section class=\"card\"><h2>Health</h2><pre>{health}</pre></section>",
            "<section class=\"card\"><h2>Deployments</h2><table><thead><tr><th>app</th><th>status</th><th>image</th></tr></thead><tbody>{rows}</tbody></table></section>",
            "</div></body></html>"
        ),
        title = escape_html(&config.title),
        health = escape_html(&health_pretty),
        rows = rows,
    );

    html_response(200, &body)
}

fn health_response(config: &Config) -> String {
    match ee_ok_response(&config.socket_path, json!({"method": "health"})) {
        Ok(health) => json_response(
            200,
            &json!({
                "ok": true,
                "service": "ee-smoke-admin",
                "easyenclave": health,
            }),
        ),
        Err(err) => json_response(
            503,
            &json!({
                "ok": false,
                "service": "ee-smoke-admin",
                "error": err,
            }),
        ),
    }
}

fn deployments_response(config: &Config) -> String {
    match ee_ok_response(&config.socket_path, json!({"method": "list"})) {
        Ok(deployments) => json_response(200, &deployments),
        Err(err) => json_response(503, &json!({"ok": false, "error": err})),
    }
}

fn ee_ok_response(socket_path: &str, request: Value) -> Result<Value, String> {
    let response = ee_request(socket_path, request)?;
    if response["ok"].as_bool() == Some(true) {
        Ok(response)
    } else {
        Err(response["error"]
            .as_str()
            .unwrap_or("easyenclave returned an unknown error")
            .to_string())
    }
}

fn ee_request(socket_path: &str, request: Value) -> Result<Value, String> {
    let mut stream =
        UnixStream::connect(socket_path).map_err(|e| format!("connect {socket_path}: {e}"))?;
    configure_socket_timeouts(&stream)?;
    ee_request_over_io(&mut stream, request)
}

fn ee_request_over_io<T: std::io::Read + std::io::Write>(
    stream: &mut T,
    request: Value,
) -> Result<Value, String> {
    let payload = serde_json::to_string(&request).map_err(|e| format!("serialize request: {e}"))?;
    stream
        .write_all(payload.as_bytes())
        .and_then(|_| stream.write_all(b"\n"))
        .map_err(|e| format!("write socket request: {e}"))?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|e| format!("read socket response: {e}"))?;
    if response.trim().is_empty() {
        return Err("easyenclave returned an empty response".into());
    }

    serde_json::from_str(response.trim_end()).map_err(|e| format!("parse socket response: {e}"))
}

fn configure_socket_timeouts(stream: &UnixStream) -> Result<(), String> {
    for (label, result) in [
        (
            "read",
            stream.set_read_timeout(Some(Duration::from_secs(5))),
        ),
        (
            "write",
            stream.set_write_timeout(Some(Duration::from_secs(5))),
        ),
    ] {
        if let Err(err) = result {
            if err.kind() == std::io::ErrorKind::PermissionDenied
                || err.kind() == std::io::ErrorKind::Unsupported
            {
                continue;
            }
            return Err(format!("set socket {label} timeout: {err}"));
        }
    }
    Ok(())
}

fn json_response(status: u16, body: &Value) -> String {
    let body = serde_json::to_string_pretty(body).unwrap_or_else(|_| "{\"ok\":false}".to_string());
    http_response(status, "application/json; charset=utf-8", &body)
}

fn html_response(status: u16, body: &str) -> String {
    http_response(status, "text/html; charset=utf-8", body)
}

fn text_response(status: u16, body: &str) -> String {
    http_response(status, "text/plain; charset=utf-8", body)
}

fn http_response(status: u16, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        reason_phrase(status),
        content_type,
        body.as_bytes().len(),
        body
    )
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "OK",
    }
}

fn escape_html(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};

    #[derive(Default)]
    struct MockStream {
        read: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl MockStream {
        fn with_response(response: &str) -> Self {
            Self {
                read: Cursor::new(response.as_bytes().to_vec()),
                written: Vec::new(),
            }
        }
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.read.read(buf)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn parse_request_line_strips_query_string() {
        let request = parse_request_line("GET /health?full=1 HTTP/1.1\r\n").unwrap();
        assert_eq!(
            request,
            RequestLine {
                method: "GET".into(),
                path: "/health".into(),
            }
        );
    }

    #[test]
    fn non_get_requests_are_rejected() {
        let response = route_request(
            &RequestLine {
                method: "POST".into(),
                path: "/health".into(),
            },
            &Config::from_env(),
        );
        assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed"));
    }

    #[test]
    fn ee_request_round_trips_json_over_line_protocol() {
        let mut stream = MockStream::with_response("{\"ok\":true,\"workloads\":0}\n");
        let response = ee_request_over_io(&mut stream, json!({"method": "health"})).unwrap();
        assert_eq!(response["ok"], true);
        assert_eq!(response["workloads"], 0);
        assert_eq!(
            String::from_utf8(stream.written).unwrap(),
            "{\"method\":\"health\"}\n"
        );
    }
}
