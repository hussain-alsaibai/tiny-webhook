# Changelog

All notable changes to tiny-webhook are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.1] - 2026-11-18

### Fixed

- **No response carried a `Content-Length`.** `_respond()` wrote the JSON body
  and stopped. Because the server speaks HTTP/1.0, the connection closes on
  finish and a direct client frames the body by EOF — so every existing test,
  and every curl in the README, looked correct. A load balancer or proxy that
  keeps the connection alive to the upstream has no boundary to work with: it
  either waits for a length that never arrives or reads the next response's
  status line as body bytes. Measured before the fix:

  ```
  GET /health -> HTTP/1.0 200 OK
                 (no Content-Length)  body 29 bytes
  ```

  Every response now declares its length.
- **A malformed `Content-Length` produced no response at all.**
  `int(self.headers.get("Content-Length", 0))` sat *outside* the `try` block,
  so `Content-Length: abc` raised `ValueError` straight out of `do_POST`.
  `BaseHTTPRequestHandler` logged the traceback and sent nothing; the client
  waited until its timeout expired. A webhook provider then retries with the
  same malformed body and the endpoint times out forever. A non-numeric or
  negative length is now a framed `400`.
- `_respond()` swallows `BrokenPipeError` / `ConnectionResetError` instead of
  letting a sender that already gave up produce a traceback. The idempotency
  guard has already recorded the attempt, so the provider's retry is
  deduplicated rather than double-processed.

### Added

- `TestResponseFraming` — six wire-level tests that open a TCP socket and
  read the bytes the server actually sends, including a `Content-Length`
  round-trip (`header value == len(body)`) for 200, 404 and 400. Verified
  against the pre-fix module: 5 of the 6 fail.

### Notes

- No API change. Handler signatures, `@app.on()` and `app.run()` are
  untouched.
- The old suite passed because it asserted on handler return values and never
  read a header. That is the gap these tests close.
