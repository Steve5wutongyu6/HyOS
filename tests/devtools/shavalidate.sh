#!/bin/bash
# 独立验证 hy_sha256（guest 原生编译，读镜像窗口，与 python sha256 对照）
set -o pipefail
T=/tmp/shatest
mkdir -p $T
cat > $T/main.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void hy_sha256(const unsigned char *data, unsigned int len, unsigned char out[32]);
int main(int argc, char **argv) {
  FILE *f = fopen(argv[1], "rb");
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  unsigned char *buf = malloc(n);
  fread(buf, 1, n, f);
  fclose(f);
  unsigned char out[32];
  hy_sha256(buf, (unsigned int)n, out);
  for (int i = 0; i < 32; i++) printf("%02x", out[i]);
  printf("\n");
  return 0;
}
EOF
cat > $T/hysha.h <<'EOF'
void hy_sha256(const unsigned char *data, unsigned int len, unsigned char out[32]);
EOF
sed -e 's|#include <grub/misc.h>||' -e 's|#include <grub/mm.h>||' -e 's|grub_memset|memset|g' -e 's|grub_memcpy|memcpy|g' -e 's|grub_malloc|malloc|g' -e 's|grub_free|free|g' -e 's|grub_uint8_t|unsigned char|g' -e 's|grub_uint32_t|unsigned int|g' -e 's|grub_uint64_t|unsigned long long|g' /mnt/vmiss/hyos-build/grub/hysha.c > $T/hysha.c
gcc -O2 -include string.h -include stdlib.h -o $T/shatest $T/main.c $T/hysha.c 2>&1 | head -5
dd if=/mnt/vmiss/hyos-build/build/deploy-test.img bs=512 skip=1 count=2047 of=$T/window.bin status=none
$T/shatest $T/window.bin > $T/hy.txt
python3 -c "import hashlib; print(hashlib.sha256(open('/tmp/shatest/window.bin','rb').read()).hexdigest())" > $T/py.txt
echo "hy_sha256: $(cat $T/hy.txt)"
echo "python   : $(cat $T/py.txt)"
cmp -s $T/hy.txt $T/py.txt && echo HASH_MATCH || echo HASH_MISMATCH
head -c 4096 $T/window.bin > $T/small.bin
$T/shatest $T/small.bin > $T/hy2.txt
python3 -c "import hashlib; print(hashlib.sha256(open('/tmp/shatest/small.bin','rb').read()).hexdigest())" > $T/py2.txt
echo "small hy: $(cat $T/hy2.txt)"; echo "small py: $(cat $T/py2.txt)"
cmp -s $T/hy2.txt $T/py2.txt && echo SMALL_MATCH || echo SMALL_MISMATCH
