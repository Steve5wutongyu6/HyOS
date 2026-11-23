#!/bin/bash
cd /mnt/vmiss/hyos-build/server
FX=/mnt/vmiss/hyos-build/tests/fixtures/dev-keys.json
OWNER=$(node -e "process.stdout.write(JSON.parse(require('fs').readFileSync(process.argv[1],'utf8')).owner_token)" $FX)
DIDV=$(node -e "process.stdout.write(JSON.parse(require('fs').readFileSync(process.argv[1],'utf8')).did)" $FX)
echo "DID=$DIDV"
curl -s -X POST http://127.0.0.1:8787/v1/rearm -H "authorization: Bearer $OWNER" -H "content-type: application/json" -d "{\"did\":\"$DIDV\"}"
echo
curl -s http://127.0.0.1:8787/v1/health
echo
