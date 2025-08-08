# Penetration Testing & Integration Guidance

## Simulated Blocking
- The `/predict` endpoint now returns HTTP 403 and a JSON message when a request is classified as malicious.
- Blocked requests are logged in `blocked_requests.log` with URL, IP, and reason.

## Penetration Testing Steps
1. Use tools like OWASP ZAP, Burp Suite, or curl/postman to send crafted requests to `/predict`.
2. Try SQLi, XSS, and other payloads in the `URL` or `request_body` fields.
3. Observe HTTP 403 and `blocked` in the response for detected attacks.
4. Check `blocked_requests.log` for details of blocked attempts.

## Integration
- Integrate with a WAF or API gateway by forwarding requests to this backend.
- Use the blocking response to trigger alerts or automated actions.
- For real-world deployment, connect the logging to SIEM or monitoring tools.

## Example curl Test
```
curl -X POST http://localhost:5000/predict -H "Content-Type: application/json" -d '{"URL": "http://test.com/?q=select+1", "request_body": "", "Method": "GET", "User-Agent": "test", "host": "localhost", "content-type": "application/json"}' -v
```
- Should return HTTP 403 and a JSON message indicating blocking.

---
For further integration or advanced pen testing, see OWASP API Security Top 10.
