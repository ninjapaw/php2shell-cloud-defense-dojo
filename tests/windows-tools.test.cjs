const test = require("node:test");
const assert = require("node:assert/strict");
const { azureCommand, windowsTool } = require("../scripts/lib/windows-tools.cjs");

const directory = "C:\\Program Files\\Microsoft SDKs\\Azure\\CLI2\\wbin";
const launcher = `${directory}\\az.cmd`;
const python = "C:\\Program Files\\Microsoft SDKs\\Azure\\CLI2\\python.exe";
const dependencies = {
  stat(path) {
    if (![launcher, python].includes(path)) throw Object.assign(new Error("not found"), { code: "ENOENT" });
    return { isFile: () => true };
  },
  read: () => "SET AZ_INSTALLER=MSI\npython.exe -IBm azure.cli",
};
test("Windows uses the installed official CLI Python module without cmd.exe or interpolated arguments", () => {
  const args = ["deployment", "sub", "what-if", "--parameters", '{"value":"spaces & quotes \\" preserved"}'];
  const plan = azureCommand(args, { Path: `"${directory}"` }, dependencies);
  assert.equal(plan.command, python);
  assert.deepEqual(plan.args, ["-IBm", "azure.cli", ...args]);
  const invocation = windowsTool("az", args, { env: { Path: directory, KEEP: "yes" } }, dependencies);
  assert.equal(invocation.options.env.AZ_INSTALLER, "MSI");
  assert.equal(invocation.options.env.KEEP, "yes");
  assert.equal(invocation.options.shell, undefined);
});
test("unrecognized Windows launchers and missing CLI fail explicitly without a shell fallback", () => {
  assert.throws(() => azureCommand([], { Path: directory }, { ...dependencies, read: () => "untrusted layout" }), /official installer|MSI\/ZIP/);
  assert.throws(() => azureCommand([], { Path: "" }, dependencies), /not found/);
});
test("Windows ZIP handling maps only the fixed application packaging to built-in tar", () => {
  assert.deepEqual(windowsTool("zip", ["-v"]).args, ["--version"]);
  const plan = windowsTool("zip", ["-q", "-r", "C:\\temp folder\\app.zip", "."], { cwd: "C:\\repo & folder\\app" });
  assert.equal(plan.command, "tar.exe");
  assert.deepEqual(plan.args, ["-a", "-c", "-f", "C:\\temp folder\\app.zip", "-C", "C:\\repo & folder\\app", "."]);
  assert.throws(() => windowsTool("zip", ["arbitrary"]), /Unsupported archive/);
});
