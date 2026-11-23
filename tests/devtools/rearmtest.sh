#!/bin/bash
FX=/mnt/vmiss/hyos-build/tests/fixtures/dev-keys.json
DID=$(node -e "process.stdout.write(JSON.parse(require('fs').readFileSync(process.argv[1],'utf8')).did)" $FX)
echo "FIXTURE_DID=$DID"
echo "--- rearm ---"
curl -s -X POST http://127.0.0.1:8787/v1/rearm -H "authorization: Bearer dev-owner-token" -H "content-type: application/json" --data-raw "{\"did\":\"$DID\"}"
echo
echo "--- ack retest ---"
bash /mnt/vmiss/hyos-build/tests/acktest.sh 2>&1 | head -2