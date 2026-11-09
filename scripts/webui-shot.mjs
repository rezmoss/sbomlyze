// Screenshot the sbomlyze web UI with a real SBOM loaded.
// usage: node scripts/webui-shot.mjs URL SBOM OUT.png
// CHROME = browser binary. Uses the DevTools pipe; no npm packages.
import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";

const [url, sbom, out] = process.argv.slice(2);
const chrome = process.env.CHROME || "google-chrome";
const proc = spawn(chrome, [
  "--headless=new", "--remote-debugging-pipe", "--no-first-run", "--disable-gpu",
  "--hide-scrollbars", "--window-size=1440,900", "about:blank",
], { stdio: ["ignore", "ignore", "inherit", "pipe", "pipe"] });

let id = 0, buf = "";
const pending = new Map();
proc.stdio[4].on("data", (d) => {
  buf += d.toString();
  let i;
  while ((i = buf.indexOf("\0")) >= 0) {
    const msg = JSON.parse(buf.slice(0, i));
    buf = buf.slice(i + 1);
    const p = pending.get(msg.id);
    if (p) {
      pending.delete(msg.id);
      msg.error ? p.reject(new Error(JSON.stringify(msg.error))) : p.resolve(msg.result);
    }
  }
});
const send = (method, params = {}, sessionId) => new Promise((ok, no) => {
  const m = { id: ++id, method, params };
  if (sessionId) m.sessionId = sessionId;
  pending.set(m.id, { resolve: ok, reject: no });
  proc.stdio[3].write(JSON.stringify(m) + "\0");
});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

try {
  const { targetId } = await send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
  const s = (m, p) => send(m, p, sessionId);
  await s("Page.enable");
  await s("DOM.enable");
  await s("Emulation.setDeviceMetricsOverride", { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
  await s("Page.navigate", { url });
  await sleep(1500);
  const { root } = await s("DOM.getDocument");
  const { nodeId } = await s("DOM.querySelector", { nodeId: root.nodeId, selector: "#file-input" });
  if (!nodeId) throw new Error("#file-input not found");
  await s("DOM.setFileInputFiles", { files: [resolve(sbom)], nodeId });
  // wait for the tree to render
  let ready = false;
  for (let i = 0; i < 60 && !ready; i++) {
    const { result } = await s("Runtime.evaluate", {
      expression: "!document.getElementById('main-content').classList.contains('hidden') && document.querySelectorAll('#tree-container *').length > 20",
      returnByValue: true,
    });
    ready = result.value === true;
    if (!ready) await sleep(500);
  }
  if (!ready) throw new Error("SBOM did not load in the web UI");
  // select the first package so the detail pane is filled
  await s("Runtime.evaluate", { expression: "(document.querySelector('#tree-container .tree-item, #tree-container [data-id]')||{}).click && document.querySelector('#tree-container .tree-item, #tree-container [data-id]').click()" });
  await sleep(1500);
  const { data } = await s("Page.captureScreenshot", { format: "png" });
  writeFileSync(out, Buffer.from(data, "base64"));
  console.log("wrote", out);
} catch (e) {
  console.error("webui-shot:", e.message);
  process.exitCode = 1;
} finally {
  proc.kill();
}
