//! A dependency-free stand-in for the AWS Lambda Runtime API, plus a helper
//! for spawning the real `bootstrap` binary against it.
//!
//! The Runtime API is plain HTTP/1.1 with no auth and three endpoints, so a
//! `TcpListener` and ~200 lines of hand-rolled parsing beat pulling a server
//! framework into the dev-dependency graph. Serving it lets a test drive a
//! Lambda binary's **actual `main`** — cold-start init included — which is the
//! only way to cover a composition root.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// What the function under test reported back for one invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// `POST /2018-06-01/runtime/invocation/{id}/response` — handler returned `Ok`.
    Response { request_id: String, body: String },
    /// `POST /2018-06-01/runtime/invocation/{id}/error` — handler returned `Err`.
    Failure { request_id: String, body: String },
    /// `POST /2018-06-01/runtime/init/error` — the runtime failed before the
    /// first invocation. Distinguished from `Failure` because it means the
    /// composition root itself is broken.
    InitError { body: String },
}

impl Outcome {
    /// The reported body, whichever variant this is.
    pub fn body(&self) -> &str {
        match self {
            Outcome::Response { body, .. }
            | Outcome::Failure { body, .. }
            | Outcome::InitError { body } => body,
        }
    }
}

struct State {
    /// `(request_id, payload)` pairs, served FIFO to successive `next` polls.
    pending: Mutex<Vec<(String, String)>>,
    outcomes: Mutex<Vec<Outcome>>,
    shutdown: AtomicBool,
}

/// A fake Lambda Runtime API bound to an ephemeral port on loopback.
///
/// Dropping it shuts the listener down and releases every parked long-poll.
pub struct FakeRuntimeApi {
    port: u16,
    state: Arc<State>,
}

impl FakeRuntimeApi {
    /// Binds a listener and queues `events`, each to be handed out once, in
    /// order. Once they are exhausted, `next` long-polls forever — exactly
    /// what real Lambda does to an idle container, and what keeps the binary
    /// alive and observable instead of racing us to exit.
    pub fn start(events: &[serde_json::Value]) -> Self {
        let pending = events
            .iter()
            .enumerate()
            .map(|(i, e)| (format!("req-{i}"), e.to_string()))
            .collect::<Vec<_>>();
        let state = Arc::new(State {
            pending: Mutex::new(pending),
            outcomes: Mutex::new(Vec::new()),
            shutdown: AtomicBool::new(false),
        });

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake Runtime API");
        let port = listener.local_addr().expect("local_addr").port();
        listener
            .set_nonblocking(true)
            .expect("set_nonblocking on listener");

        let accept_state = state.clone();
        thread::spawn(move || accept_loop(listener, accept_state));

        Self { port, state }
    }

    /// The `host:port` value to pass as `AWS_LAMBDA_RUNTIME_API`.
    pub fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// Everything reported so far.
    pub fn outcomes(&self) -> Vec<Outcome> {
        self.state.outcomes.lock().expect("outcomes lock").clone()
    }
}

impl Drop for FakeRuntimeApi {
    fn drop(&mut self) {
        self.state.shutdown.store(true, Ordering::SeqCst);
    }
}

fn accept_loop(listener: TcpListener, state: Arc<State>) {
    while !state.shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let state = state.clone();
                thread::spawn(move || handle_conn(stream, state));
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => return,
        }
    }
}

/// Serves one connection until the peer closes it or the API shuts down.
/// The Lambda runtime client keeps the connection alive across polls, so this
/// must loop rather than handle a single request.
fn handle_conn(mut stream: TcpStream, state: Arc<State>) {
    // Short read timeout so a parked long-poll still notices shutdown.
    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
    while let Some((method, path, body)) = read_request(&mut stream, &state) {
        if !respond(&mut stream, &state, &method, &path, &body) {
            return;
        }
    }
}

/// Reads one complete request. Returns `None` when the peer closed the
/// connection, the API is shutting down, or the request is unparseable.
fn read_request(stream: &mut TcpStream, state: &State) -> Option<(String, String, Vec<u8>)> {
    let mut buf = Vec::new();
    let head_end = loop {
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        read_more(stream, state, &mut buf)?;
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut request_line = head.lines().next()?.split_whitespace();
    let method = request_line.next()?.to_string();
    let path = request_line.next()?.to_string();

    let content_length = head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);

    while buf.len() < head_end + content_length {
        read_more(stream, state, &mut buf)?;
    }
    let body = buf[head_end..head_end + content_length].to_vec();
    Some((method, path, body))
}

/// Appends one chunk to `buf`. `None` means "stop reading this connection":
/// either EOF or shutdown. A read timeout is not an error — it is how a parked
/// long-poll gets a chance to re-check the shutdown flag.
fn read_more(stream: &mut TcpStream, state: &State, buf: &mut Vec<u8>) -> Option<()> {
    let mut chunk = [0u8; 8192];
    loop {
        if state.shutdown.load(Ordering::SeqCst) {
            return None;
        }
        match stream.read(&mut chunk) {
            Ok(0) => return None,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                return Some(());
            }
            Err(ref e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return None,
        }
    }
}

/// Writes the reply for one request. Returns `false` if the connection should
/// be dropped.
fn respond(stream: &mut TcpStream, state: &State, method: &str, path: &str, body: &[u8]) -> bool {
    let body = String::from_utf8_lossy(body).into_owned();

    if method == "GET" && path == "/2018-06-01/runtime/invocation/next" {
        let Some((request_id, payload)) = next_event(state) else {
            // Shutdown while parked. Drop the connection; the child is about
            // to be killed anyway.
            return false;
        };
        let deadline_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
            + 60_000;
        let head = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Lambda-Runtime-Aws-Request-Id: {request_id}\r\n\
             Lambda-Runtime-Deadline-Ms: {deadline_ms}\r\n\
             Lambda-Runtime-Invoked-Function-Arn: \
             arn:aws:lambda:us-east-1:000000000000:function:testkit\r\n\
             Lambda-Runtime-Trace-Id: Root=1-00000000-000000000000000000000000\r\n\
             \r\n",
            payload.len()
        );
        return write_all(stream, head.as_bytes()) && write_all(stream, payload.as_bytes());
    }

    if method == "POST" {
        // Parallel dispatch reads clearer than the `.map()` clippy suggests for
        // the last arm alone.
        #[allow(clippy::manual_map)]
        let outcome = if path == "/2018-06-01/runtime/init/error" {
            Some(Outcome::InitError { body })
        } else if let Some(request_id) = strip_invocation(path, "/response") {
            Some(Outcome::Response { request_id, body })
        } else if let Some(request_id) = strip_invocation(path, "/error") {
            Some(Outcome::Failure { request_id, body })
        } else {
            None
        };
        if let Some(outcome) = outcome {
            state.outcomes.lock().expect("outcomes lock").push(outcome);
            return write_all(
                stream,
                b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n",
            );
        }
    }

    write_all(
        stream,
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
    )
}

/// Pops the next queued event, parking until one exists or the API shuts down.
fn next_event(state: &State) -> Option<(String, String)> {
    loop {
        if state.shutdown.load(Ordering::SeqCst) {
            return None;
        }
        if let Some(event) = {
            let mut pending = state.pending.lock().expect("pending lock");
            (!pending.is_empty()).then(|| pending.remove(0))
        } {
            return Some(event);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// `/2018-06-01/runtime/invocation/{id}{suffix}` -> `Some(id)`.
fn strip_invocation(path: &str, suffix: &str) -> Option<String> {
    let rest = path.strip_prefix("/2018-06-01/runtime/invocation/")?;
    Some(rest.strip_suffix(suffix)?.to_string())
}

fn write_all(stream: &mut TcpStream, bytes: &[u8]) -> bool {
    stream.write_all(bytes).is_ok() && stream.flush().is_ok()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The real `bootstrap` binary, running as a child process.
///
/// Killed on drop, so a failing assertion can never leave a Lambda polling a
/// dead listener.
pub struct LambdaProcess {
    child: Child,
    log: Arc<Mutex<String>>,
}

impl LambdaProcess {
    /// Spawns `binary` wired to `runtime_api`, with a **cleared** environment
    /// plus `extra_env`.
    ///
    /// Clearing matters: an ambient `AWS_PROFILE`, `AWS_REGION`, or real
    /// credentials on a developer machine would otherwise leak into the child
    /// and make the test pass or fail for reasons unrelated to the code.
    pub fn spawn<K, V>(binary: &str, runtime_api: &str, extra_env: &[(K, V)]) -> Self
    where
        K: AsRef<std::ffi::OsStr>,
        V: AsRef<std::ffi::OsStr>,
    {
        let mut command = Command::new(binary);
        command
            .env_clear()
            // Only what a statically-linked Rust binary genuinely needs.
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/tmp")
            .env("AWS_LAMBDA_RUNTIME_API", runtime_api)
            .env("AWS_LAMBDA_FUNCTION_NAME", "cloudtrail-rs-testkit")
            .env("AWS_LAMBDA_FUNCTION_VERSION", "$LATEST")
            .env("AWS_LAMBDA_FUNCTION_MEMORY_SIZE", "512")
            .env("AWS_LAMBDA_LOG_GROUP_NAME", "/aws/lambda/cloudtrail-rs")
            .env("AWS_LAMBDA_LOG_STREAM_NAME", "testkit")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in extra_env {
            command.env(key, value);
        }

        let mut child = command
            .spawn()
            .unwrap_or_else(|e| panic!("spawning {binary}: {e}"));

        let log = Arc::new(Mutex::new(String::new()));
        for pipe in [
            child.stdout.take().map(PipeKind::Out),
            child.stderr.take().map(PipeKind::Err),
        ]
        .into_iter()
        .flatten()
        {
            let log = log.clone();
            thread::spawn(move || drain(pipe, log));
        }

        Self { child, log }
    }

    /// Everything the child has written to stdout/stderr so far. Attach this
    /// to any assertion failure — the Lambda's own tracing output is usually
    /// the whole diagnosis.
    pub fn logs(&self) -> String {
        self.log.lock().expect("log lock").clone()
    }

    /// Blocks until `api` has recorded at least `n` outcomes, panicking with
    /// the child's logs if it exits first or `timeout` elapses.
    ///
    /// Liveness is polled alongside the outcome count on purpose: a
    /// composition root that panics during init never reaches the runtime
    /// loop, so it reports *nothing* — waiting on the count alone would burn
    /// the full timeout and then fail with no explanation. Catching the exit
    /// turns that into an immediate failure quoting the panic.
    pub fn wait_for_outcomes(
        &mut self,
        api: &FakeRuntimeApi,
        n: usize,
        timeout: Duration,
    ) -> Vec<Outcome> {
        let deadline = Instant::now() + timeout;
        loop {
            let outcomes = api.outcomes();
            // An init error is terminal — the runtime exits rather than poll
            // again, so returning early keeps the failure message useful.
            if outcomes.len() >= n
                || outcomes
                    .iter()
                    .any(|o| matches!(o, Outcome::InitError { .. }))
            {
                return outcomes;
            }
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!(
                    "lambda exited with {status} after reporting {} of {n} outcome(s)\n\
                     ---- child output ----\n{}",
                    outcomes.len(),
                    self.logs()
                );
            }
            if Instant::now() >= deadline {
                panic!(
                    "timed out after {timeout:?} waiting for {n} outcome(s); got {}\n\
                     ---- child output ----\n{}",
                    outcomes.len(),
                    self.logs()
                );
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// Asserts the function reported exactly one successful invocation and
    /// returns its body.
    pub fn expect_one_response(&mut self, api: &FakeRuntimeApi, timeout: Duration) -> String {
        let outcomes = self.wait_for_outcomes(api, 1, timeout);
        match outcomes.first() {
            Some(Outcome::Response { body, .. }) => body.clone(),
            other => panic!(
                "expected a successful invocation, got {other:?}\n\
                 ---- child output ----\n{}",
                self.logs()
            ),
        }
    }
}

impl Drop for LambdaProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

enum PipeKind {
    Out(std::process::ChildStdout),
    Err(std::process::ChildStderr),
}

fn drain(pipe: PipeKind, log: Arc<Mutex<String>>) {
    let mut reader: Box<dyn Read> = match pipe {
        PipeKind::Out(out) => Box::new(out),
        PipeKind::Err(err) => Box::new(err),
    };
    let mut chunk = [0u8; 4096];
    while let Ok(n) = reader.read(&mut chunk) {
        if n == 0 {
            return;
        }
        log.lock()
            .expect("log lock")
            .push_str(&String::from_utf8_lossy(&chunk[..n]));
    }
}
