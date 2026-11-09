"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

class Element {
  constructor(tag) { this.tagName = tag; this.nodeType = 1; this.children = []; this.style = {}; this.value = ""; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
  setAttribute(name, value) { this[name] = value; }
  addEventListener() {}
  focus() {}
  get textContent() { return this.children.map(node => node.textContent || "").join(""); }
  set textContent(value) { this.children = [{ nodeType: 3, textContent: String(value) }]; }
}
const status = () => ({ version: "test", pid: 1, observed_at: "now",
  transport: { paths: [{ healthy: false }] },
  config: { bonding_mode: true, mtu: 1280, client_tunnel_ip: "10.77.0.2", bind: [["0.0.0.0",4433]] },
  packets: {} });
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const flush = () => new Promise(resolve => setImmediate(resolve));
async function browser(initialStatus = () => status()) {
  const nodes = Object.fromEntries(["view","notice","nav","refresh"].map(id => [id,new Element("div")]));
  const listeners = {}, intervals = new Map(); let nextTimer = 0;
  const state = { statusProvider: initialStatus, statusRequests: 0 };
  const context = vm.createContext({
    document: { getElementById: id => nodes[id], createElement: tag => new Element(tag),
      createTextNode: value => ({nodeType:3,textContent:String(value)}) },
    window: { addEventListener: (name,fn) => { (listeners[name] ||= []).push(fn); } },
    location: { hash: "#/status/overview" },
    setInterval: fn => { const id=++nextTimer;intervals.set(id,fn);return id; },
    clearInterval: id => intervals.delete(id), setTimeout: () => ++nextTimer,
    fetch: async url => {
      let data;
      if (url === "/api/session") data={authenticated:true,csrf:"test"};
      else if (url === "/api/status") { state.statusRequests++;data=await state.statusProvider(); }
      else if (url === "/api/config") data={text:'{"mtu":1280}'};
      else if (url === "/api/interfaces") data={data:[]};
      else throw new Error("Unexpected URL: "+url);
      return {status:200,ok:true,json:async()=>data};
    },
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname,"../gamebond/admin/static/app.js"),"utf8"),context);
  await flush();
  return { nodes, intervals, state, context, navigate: async hash => {
    context.location.hash=hash;
    await Promise.all((listeners.hashchange || []).map(fn=>fn()));
    await flush();
  } };
}

test("late initial Status response cannot replace Configuration or unsaved edits",async()=>{
  const pending=deferred();const b=await browser(()=>pending.promise);
  await b.navigate("#/system/config");
  const editor=b.nodes.view.children.find(node=>node.tagName==="textarea");
  editor.value="unsaved change";
  pending.resolve(status());await flush();
  assert.match(b.nodes.view.textContent,/Configuration/);
  assert.equal(b.nodes.view.children.find(node=>node.tagName==="textarea"),editor);
  assert.equal(editor.value,"unsaved change");
  assert.equal(b.nodes.notice.children.length,0,"old Overview must not display its notice on another page");
  assert.equal(b.intervals.size,0,"an obsolete route must not reinstall its auto-refresh timer");
});

test("an in-flight periodic Status refresh cannot overwrite Interfaces",async()=>{
  const b=await browser();const pending=deferred();
  b.state.statusProvider=()=>pending.promise;
  const tick=[...b.intervals.values()][0];assert.equal(typeof tick,"function");
  const work=tick();
  await b.navigate("#/network/interfaces");
  pending.resolve(status());await work;await flush();
  assert.match(b.nodes.view.textContent,/Interfaces/);
  assert.equal(b.intervals.size,0);
});

test("late refresh errors cannot replace the newly selected page",async()=>{
  const pending=deferred();const b=await browser(()=>pending.promise);
  await b.navigate("#/system/config");
  pending.reject(new Error("old refresh failed"));await flush();
  assert.match(b.nodes.view.textContent,/Configuration/);
  assert.doesNotMatch(b.nodes.view.textContent,/old refresh failed/);
});

test("slow periodic requests do not overlap",async()=>{
  const b=await browser();const pending=deferred();
  b.state.statusProvider=()=>pending.promise;
  const tick=[...b.intervals.values()][0],before=b.state.statusRequests;
  const first=tick(),second=tick();
  assert.equal(b.state.statusRequests-before,1);
  pending.resolve(status());await Promise.all([first,second]);
  assert.match(b.nodes.view.textContent,/Status/);
});
