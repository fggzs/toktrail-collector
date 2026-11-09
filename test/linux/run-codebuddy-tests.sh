#!/bin/sh
# CodeBuddy history 适配器 Linux 验证脚本（对应合并后的语义）
#
# 覆盖点：
#   1. XDG 布局下的会话索引发现（.../CodeBuddyExtension/Data/<user>/CodeBuddyIDE/...）
#   2. 目录级授权扫描：records/quarantined 计数
#   3. 模型归属：assistant 消息归属 + requestId 自证的 user 消息兜底
#   4. 缺失 startedAt 的请求被隔离（不再用消息文件 mtime 兜底）
#   5. 缺失缓存拆分的请求被隔离
#   6. streaming / 全零 usage 行静默跳过
#   7. 单文件授权不读兄弟消息文件（模型回落 unknown）
#
# 用法：sh run-codebuddy-tests.sh [BIN=/path/to/toktrail]
# 说明：XDG 默认目录探测（connect / 定时 grant 同步路径）需要真实服务端
#       ticket，本脚本无法覆盖，只能由单元测试与真机 connect 验证。

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
bin=${BIN:-}
if [ -z "$bin" ]; then
  case "$(uname -m)" in
    x86_64|amd64) bin=$here/toktrail-linux-amd64 ;;
    aarch64|arm64) bin=$here/toktrail-linux-arm64 ;;
    *) echo "unsupported arch: $(uname -m)" >&2; exit 2 ;;
  esac
fi
[ -f "$bin" ] || { echo "binary not found: $bin" >&2; exit 2; }
# 从 Windows 打包的 tar 会丢失可执行位，这里自愈一次再继续。
if [ ! -x "$bin" ]; then
  chmod +x "$bin" 2>/dev/null || true
fi
[ -x "$bin" ] || { echo "binary not executable (chmod +x failed): $bin" >&2; exit 2; }

work=${WORK:-$(mktemp -d)}
state=$work/state
data=$work/home/.local/share/CodeBuddyExtension/Data
conv=$data/u1/CodeBuddyIDE/u1/history/ws/conv1
mkdir -p "$conv/messages" "$state"

fail=0
check() { # check <name> <want> <got>
  if [ "$2" = "$3" ]; then
    echo "PASS $1 = $3"
  else
    echo "FAIL $1: want $2, got $3"
    fail=1
  fi
}
field() { # field <text> <key>  -> 文本中 "<key>=<n>" 里的 n
  printf '%s\n' "$1" | tr ' ' '\n' | sed -n "s/^$2=\([0-9][0-9]*\)$/\1/p" | head -n 1
}

# 一份会话索引：r1 正常、r2 只有 user 消息（模型兜底）、r3 无 startedAt、
# r4 streaming、r5 缺缓存拆分、r6 全零。
cat > "$conv/index.json" <<'JSON'
{
  "messages": [
    {"id":"m1","type":"text","role":"user","isComplete":true},
    {"id":"m2","type":"text","role":"assistant","isComplete":true},
    {"id":"m3","type":"text","role":"user","isComplete":true}
  ],
  "requests": [
    {"id":"r1","type":"craft","messages":["m1","m2"],"state":"complete","startedAt":1791014053528,
     "usage":{"inputTokens":1000,"outputTokens":10,"totalTokens":1010,"lastTokens":0,
              "cacheTokens":400,"cachedWriteTokens":0,"cachedMissTokens":600}},
    {"id":"r2","type":"craft","messages":["m3"],"state":"complete","startedAt":1791014424445,
     "usage":{"inputTokens":1000,"outputTokens":5,"totalTokens":1005,
              "cacheTokens":0,"cachedWriteTokens":0,"cachedMissTokens":0}},
    {"id":"r3","type":"craft","messages":["m1"],"state":"complete",
     "usage":{"inputTokens":100,"outputTokens":10,"totalTokens":110,
              "cacheTokens":0,"cachedWriteTokens":0}},
    {"id":"r4","type":"craft","messages":["m1"],"state":"streaming","startedAt":1791045445333,
     "usage":{"inputTokens":5000,"outputTokens":10,"totalTokens":5010,
              "cacheTokens":0,"cachedWriteTokens":0}},
    {"id":"r5","type":"craft","messages":["m1"],"state":"complete","startedAt":1791045445333,
     "usage":{"inputTokens":100,"outputTokens":10,"totalTokens":110}},
    {"id":"r6","type":"craft","messages":["m1"],"state":"complete","startedAt":1791045445333,
     "usage":{"inputTokens":0,"outputTokens":0,"totalTokens":0,
              "cacheTokens":0,"cachedWriteTokens":0,"cachedMissTokens":0}}
  ]
}
JSON

# extra 是 JSON 编码后的字符串，rollout 里就是这个形状。
cat > "$conv/messages/m1.json" <<'JSON'
{"role":"user","message":"{}","id":"m1","extra":"{\"requestId\":\"r1\"}"}
JSON
cat > "$conv/messages/m2.json" <<'JSON'
{"role":"assistant","message":"{}","id":"m2","extra":"{\"requestId\":\"r1\",\"modelId\":\"hy4-preview-ioa\"}"}
JSON
cat > "$conv/messages/m3.json" <<'JSON'
{"role":"user","message":"{}","id":"m3","extra":"{\"requestId\":\"r2\",\"modelId\":\"glm-5.2\",\"modelName\":\"GLM-5.2\"}"}
JSON

echo "== 目录级扫描: $data"
scan_out=$("$bin" scan --source codebuddy-history --input "$data" --state-dir "$state")
printf '%s\n' "$scan_out" | grep -E 'source=|quarantined=|issue\[' || true
check "records" 2 "$(field "$scan_out" records)"
check "valid" 2 "$(field "$scan_out" valid)"
check "quarantined" 2 "$(field "$scan_out" quarantined)"

echo "== 导出批次"
batch=$work/batch.json
export_out=$("$bin" export --source codebuddy-history --input "$data" --out "$batch" --batch test-1 --state-dir "$state")
printf '%s\n' "$export_out" | head -n 3
check "batch records" 2 "$(grep -o '"recordKey"' "$batch" | wc -l | tr -d ' ')"
check "assistant 归属" 1 "$(grep -c 'hy4-preview-ioa' "$batch" || true)"
check "user 兜底归属" 1 "$(grep -c 'glm-5.2' "$batch" || true)"
check "没有 unknown 模型" 0 "$(grep -c '"model": "unknown"' "$batch" || true)"

echo "== 单文件授权只读该索引"
state2=$work/state-single
mkdir -p "$state2"
single_out=$("$bin" scan --source codebuddy-history --input "$conv/index.json" --state-dir "$state2")
check "单文件 records" 2 "$(field "$single_out" records)"
single_batch=$work/single.json
"$bin" export --source codebuddy-history --input "$conv/index.json" --out "$single_batch" --batch test-2 --state-dir "$state2" >/dev/null
check "单文件模型回落 unknown" 2 "$(grep -c '"model": "unknown"' "$single_batch" || true)"

echo "== 版本与帮助"
ver=$("$bin" version)
case "$ver" in
  "toktrail "*) echo "PASS version = $ver" ;;
  *) echo "FAIL version: $ver"; fail=1 ;;
esac

if [ "$fail" -ne 0 ]; then
  echo "RESULT: FAILED (work dir: $work)" >&2
  exit 1
fi
echo "RESULT: ALL PASSED (work dir: $work)"
