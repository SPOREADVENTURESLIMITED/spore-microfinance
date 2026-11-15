const fs = require("node:fs");
const vm = require("node:vm");
const html = fs.readFileSync("public/account.html", "utf8");
const start = html.indexOf("<script>\nconst $");
const end = html.lastIndexOf("</script>");
if (start < 0 || end <= start) throw new Error("Main account portal script block was not found.");
new vm.Script(html.slice(start + 8, end), { filename: "public/account.html inline script" });
console.log("Portal inline JavaScript syntax is valid.");
