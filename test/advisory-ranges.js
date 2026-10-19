"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {scan} = require("../src/scanner");
const cases = [
 ["cwj3-vqpp-pmxr", "2026.4.22", "2026.4.23"],
 ["p73f-w79w-jqr5", "2026.5.5", "2026.5.6"],
 ["j472-gf56-x589", "2026.5.7", "2026.5.8"],
 ["77q5-rr5v-x43q", "2026.5.6", "2026.5.7"],
 ["w5ww-7chg-mxcq", "2026.5.5", "2026.5.6"],
 ["7hxm-f538-3xp6", "2026.5.6", "2026.5.7"],
];
for (const [id,bad,outside] of cases) test(id + " respects published range", async t => {
 const root=fs.mkdtempSync(path.join(os.tmpdir(),"advisory-"));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 for (const [version,expected] of [[bad,true],[outside,false],["2026.5.12",false]]) {
  fs.writeFileSync(path.join(root,"package.json"), JSON.stringify({name:"openclaw",version}));
  const findings=(await scan(root)).findings.filter(f=>f.message.includes(id));
  assert.equal(findings.length>0,expected,version);
  if(expected) assert.match(findings[0].message,/does not establish exploitability/);
 }
});
for(const version of ["^2026.1.1","~2026.1.1",">=2026.1.1","^2026.5.5",">=2026.5.5","2026.5.7-beta.1","latest","x2026.5.5"])
 test("uncertain spec stays review: " + version, async t=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),"advisory-"));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  fs.writeFileSync(path.join(root,"package.json"),JSON.stringify({dependencies:{openclaw:version}}));
  const hits=(await scan(root)).findings;
  assert(hits.some(f=>f.type==="openclaw-version-review" && f.severity === "high"));
  assert(!hits.some(f=>f.type==="vulnerable-openclaw-version"));
 });

for (const [version, vulnerable] of [["=2026.1.1",true],["= 2026.5.7",true],["=2026.5.8",false]])
 test("npm equality pin: " + version, async t => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),"advisory-"));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  fs.writeFileSync(path.join(root,"package.json"),JSON.stringify({dependencies:{openclaw:version}}));
  const hits=(await scan(root)).findings;
  assert(!hits.some(f=>f.type==="openclaw-version-review"));
  assert.equal(hits.some(f=>f.type==="vulnerable-openclaw-version"),vulnerable);
 });
