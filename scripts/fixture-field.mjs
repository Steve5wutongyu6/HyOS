// 读取 fixture 字段：node fixture-field.mjs <file> <field>
import { readFileSync } from "node:fs";
const fx = JSON.parse(readFileSync(process.argv[2], "utf8"));
process.stdout.write(String(fx[process.argv[3]] ?? ""));