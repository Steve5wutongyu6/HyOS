#!/bin/bash
L=/mnt/vmiss/hyos-build/build/logs
for s in e1 e2 e3 e4 e5 e6 e7 e8 e9; do
  echo "=== $s ==="
  grep -aoE "HYOS SELFTEST OK|HYOS BOOT-CHAIN OK epoch=[0-9]+|HYVERIFY GRUB-CHAIN OK|SYS_OK|APP_OK sealed|ADVANCE OK seq=[0-9]+|HYOS E2E SUCCESS|HYOS DESTROY|HYOS WIPED|payload-tag|grub_ok-refused|system-manifest|os-pin|HYOS L5 WIPE|HB_FAIL [0-9]+|NET UP eth0 [0-9.]+/24" $L/$s.log 2>/dev/null | head -12
done
echo "=== contract ==="
grep -ac "^PASS" $L/contract.txt 2>/dev/null
grep -a "contract:" $L/contract.txt 2>/dev/null | tail -1