const fs = require("fs");
const p = process.argv[2];
let s = fs.readFileSync(p, "utf8");
s = s.split(String.fromCharCode(10)).filter(l => !l.includes("include <string.h>")).join(String.fromCharCode(10));
s = s.replace(/(^|[^_a-zA-Z0-9])memcpy\(/g, "$1grub_memcpy(");
s = s.replace(/(^|[^_a-zA-Z0-9])memset\(/g, "$1grub_memset(");
s = s.replace("#include \"aes.h\"", "#include \"aes.h\"\n#include <grub/misc.h>");
fs.writeFileSync(p, s);
console.log("aes adapted for freestanding");
