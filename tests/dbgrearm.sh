#!/bin/bash
grep -n "OWNER=" /mnt/vmiss/hyos-build/tests/e2e.sh | head -4
grep -n "DIDV=" /mnt/vmiss/hyos-build/tests/e2e.sh | head -4
grep -n "v1/rearm" /mnt/vmiss/hyos-build/tests/e2e.sh | head -4
echo ===PARSE_TEST===
FX=/mnt/vmiss/hyos-build/tests/fixtures/dev-keys.json
node -e "const f=JSON.parse(require('fs').readFileSync(process.argv[1],'utf8')); process.stdout.write('did='+f.did+' owner='+f.owner_token.slice(0,6))" $FX
echo
