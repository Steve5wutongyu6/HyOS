#!/bin/bash
# E2E 启动器：精确模式避免任何自匹配
for p in $(pgrep -f "tests/e2e\.sh"); do kill -9 "$p" 2>/dev/null; done
for p in $(pgrep -f "[q]emu-system"); do kill -9 "$p" 2>/dev/null; done
sleep 1
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
LOG=${1:-/tmp/e2e_run.log}
bash /mnt/vmiss/hyos-build/tests/e2e.sh > "$LOG" 2>&1
echo "E2E_EXIT=$?" >> "$LOG"