#!/usr/bin/env bash
# 全量门 —— 一条命令跑完 CI 会跑的每一道。
#
# 🔴 存在的理由是两次实际失败（2026-09-14，同一天）：`ruff format --check` 在施工单的
# 全量门清单里，而两次都是我【逐条手敲那份清单时漏掉了它】。第一次由 review 抓出，
# 第二次我自己在提交前又漏了同一条。
#
# ⇒ 处置不是"下次记得"：**把清单换成一条命令**。一份要人逐条敲的清单会漏，
#    而漏掉的那一条恰恰是清单的作者自己写下的那一条 —— 因为写的人以为自己记得。
#
# ⚠️ 本脚本必须与 `.github/workflows/ci.yml` 保持同一组门。两处各写一份就是
#    "一个必须永远相等的东西出现在两处"——所以这里【只】加一条 CI 之外的本地门
#    （check_shape_match，CI 里由别处触发），其余逐条对应，改动时两边一起改。
#
# 用法：  bash tools/gates.sh          # 全跑，任一道红即非零退出
#         bash tools/gates.sh --fix    # 先自动修可修的（format / ruff --fix），再全跑
set -uo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="$PWD:$PWD/lib/python3.12/site-packages"
BIN=./bin
[ -x "$BIN/ruff" ] || BIN=""   # 没有本地 venv 时退回 PATH 上的工具

if [ "${1:-}" = "--fix" ]; then
  echo "== 自动修（format / ruff --fix）=="
  ${BIN:+$BIN/}ruff check --fix . || true
  ${BIN:+$BIN/}ruff format . || true
fi

fail=0
run() {   # run <名字> <命令...>
  local name="$1"; shift
  printf '\n== %s ==\n' "$name"
  if "$@"; then
    printf '   ✅ %s\n' "$name"
  else
    printf '   🔴 %s 未通过\n' "$name"
    fail=1
  fi
}

run "ruff check"        ${BIN:+$BIN/}ruff check .
run "ruff format"       ${BIN:+$BIN/}ruff format --check .
run "mypy"              ${BIN:+$BIN/}mypy tools treval
run "pytest"            ${BIN:+$BIN/}pytest tests/ -q
run "bandit"            ${BIN:+$BIN/}bandit -q -r tools treval
run "披露门"             python3 tools/check_disclosure.py
run "形状门"             python3 -m tools.check_shape_match

# 🔴 纪律② 的自查 —— 对【本次改动的新增行】扫，不对记忆里的字符串 grep。
#
# 起因是 2026-09-15 一次实际失败：我报了"复查 grep 零命中"，而同一批新增行里还剩六处
# 实测件数 —— 我 grep 的是【我记得自己写过的那几句】，不是【我这次真正加了什么】。
#
# 🔴 只扫【被测方实测值】，不扫【我们自己的裁定日期】：
#   违规    "报 1.0" · "n=134" · "113/134" · "9 件"         —— 被测方的数
#   不违规  "Platform 2026-09-13 定案" · "2026-07-01 定死"  —— 我们自己的决策留痕，
#           它让人查得到谁在什么时候决定了什么，去掉它反而更糟
# ⚠️ 第一版把两类一起扫 ⇒ 十条命中里八条是裁定日期 ⇒ 那是【假红】，
#    而假红一样贵：它训练人去忽略这条提醒。
#
# ⚠️ 它不是 CI 的一道门（纪律② 点名的三样里今天只有 sha 有机械模式），是一条提醒：
#    命中不等于违规（"件A/件B" 这类编号会命中），所以它只打印、不改退出码。
printf '\n== 纪律② 自查（被测方实测值出现在新增行里）==\n'
# 🔴 2026-09-25 补两个盲点 —— 它们让本自查漏掉了七处真违规（提交前逐个人工扫出来的）：
#   ① 射程只有 treval/ tools/，不含 tests/ —— 而 tests/ 也是公开仓代码
#   ② 只看 `git diff HEAD`，看不见【未跟踪文件】—— 而一整轮的新文件全是未跟踪的
# ⚠️ ②是更重的那个：一个"新加的文件"在本自查眼里与"没加文件"完全同形。
# ⇒ 改成 diff（已跟踪的改动）∪ 未跟踪文件全文，两路都扫。
{ git diff HEAD -- treval/ tools/ tests/ 2>/dev/null | grep -E '^\+'
  git ls-files --others --exclude-standard -- treval/ tools/ tests/ 2>/dev/null \
    | while IFS= read -r nf; do sed 's/^/+/' "$nf"; done
} \
  | grep -nE '[0-9]+ 件|[0-9]+/[0-9]+ |报 [0-9]|n=[0-9]+|ci_(low|high) *[=＝] *[0-9]' \
  | grep -vE '件A|件B|件C|件⑧|0 件已量|§|EV-|LLM0' \
  || printf '   ✅ 新增行里没有被测方实测值\n'

printf '\n'
if [ "$fail" -eq 0 ]; then
  printf '✅ 全量门通过\n'
else
  # 🔴 非零退出，且把"哪几道红了"留在上面逐行 —— 不汇总成一句
  # （一句"有门红了"会让人去猜是哪一道，而猜错的成本正是这个脚本要省掉的）。
  printf '🔴 有门未通过（见上）\n'
fi
exit "$fail"
