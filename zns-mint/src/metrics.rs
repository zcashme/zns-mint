use prometheus::register_int_gauge;
use prometheus::Encoder;
use prometheus::TextEncoder;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

pub fn set_boot_success(success: bool) {
    register_int_gauge!(
        "zns_mint_boot_success",
        "Boot success, 1 for success and 0 for failure"
    )
    .unwrap()
    .set(if success { 1 } else { 0 });
}

pub fn serve_metrics() {
    let listener = TcpListener::bind("127.0.0.1:9898").expect("metrics listener bind failed");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(stream) => stream,
                Err(err) => {
                    tracing::warn!(%err, "metrics: accept failed");
                    continue;
                }
            };

            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let request = String::from_utf8_lossy(&buf);
            let path = request.split_whitespace().nth(1).unwrap_or("/");

            if path != "/metrics" {
                let response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nnot found";
                let _ = stream.write_all(response);
                continue;
            }

            let encoder = TextEncoder::new();
            let metric_families = prometheus::gather();
            let mut body = Vec::new();
            if let Err(err) = encoder.encode(&metric_families, &mut body) {
                tracing::warn!(%err, "metrics: encode failed");
                let response =
                    b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 21\r\nConnection: close\r\n\r\nmetrics encode failed";
                let _ = stream.write_all(response);
                continue;
            }

            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                encoder.format_type(),
                body.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(&body);
        }
    });
}
