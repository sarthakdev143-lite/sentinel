import std/[httpclient, json, strutils, os]

# Minimal repro: same URL the agent uses
let token = "123:STUB"
let url = "https://api.telegram.org/bot" & token & "/sendMessage"
echo "URL: ", url

let client = newHttpClient(
  userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
  timeout = 10000
)
client.headers = newHttpHeaders({
  "Content-Type": "application/json",
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
})

let body = $ %*{"chat_id": "12345", "text": "test"}
echo "Body: ", body

try:
  let resp = client.post(url, body = body)
  echo "Status: ", resp.status
  echo "Body: ", resp.body[0..<min(200, resp.body.len)]
except CatchableError as e:
  echo "Error: ", e.msg
