"use strict";

const http = require("http");
const https = require("https");
const path = require("path");
const readline = require("readline");
const egress = require("./egress-profiles.js");

const COMMANDS = new Set(["list", "add", "test", "enable", "disable", "remove"]);

function usage(stream = process.stderr) {
  stream.write(`Usage:
  node mcp/core/egress-cli.js [project-dir] list [--json]
  node mcp/core/egress-cli.js [project-dir] add <name> [--proxy-env ENV] [--proxy-url URL] [--region REGION] [--description TEXT] [--disabled] [--json]
  node mcp/core/egress-cli.js [project-dir] test <name> [--url URL] [--json]
  node mcp/core/egress-cli.js [project-dir] enable <name> [--json]
  node mcp/core/egress-cli.js [project-dir] disable <name> [--json]
  node mcp/core/egress-cli.js [project-dir] remove <name> --yes [--json]
`);
}

function parse(argv, env = process.env) {
  const args = argv.slice();
  let projectDir = env.BOB_PROJECT_DIR || process.cwd();
  if (args[0] && !args[0].startsWith("-") && !COMMANDS.has(args[0])) {
    projectDir = args.shift();
  }
  const command = COMMANDS.has(args[0]) ? args.shift() : "list";
  return {
    projectDir: path.resolve(projectDir),
    command,
    args,
    json: args.includes("--json"),
  };
}

function flagValue(args, flag) {
  const index = args.indexOf(flag);
  if (index < 0) return null;
  return args[index + 1] && !args[index + 1].startsWith("--") ? args[index + 1] : "";
}

function firstPositional(args) {
  return args.find((arg, index) => (
    !arg.startsWith("-") &&
    (index === 0 || !args[index - 1].startsWith("--"))
  ));
}

function envRefForProfile(name) {
  const envName = `BOB_EGRESS_${String(name).replace(/[^A-Za-z0-9]+/g, "_").replace(/^_+|_+$/g, "").toUpperCase()}_PROXY`;
  return `\${${envName || "BOB_EGRESS_PROFILE_PROXY"}}`;
}

function printResult(result, json, stdout = process.stdout) {
  if (json) {
    stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }
  if (Array.isArray(result.profiles)) {
    for (const profile of result.profiles) {
      const enabled = profile.enabled ? "enabled" : "disabled";
      const proxy = profile.proxy_configured ? "yes" : "no";
      const region = profile.region || "-";
      const description = profile.description || "";
      stdout.write(`${profile.name}\t${enabled}\tregion=${region}\tproxy=${proxy}\t${description}\n`);
    }
    return;
  }
  if (result.message) stdout.write(`${result.message}\n`);
  if (result.profile) {
    const p = result.profile;
    stdout.write(`Profile: ${p.name} (${p.enabled ? "enabled" : "disabled"}), region=${p.region || "-"}, proxy=${p.proxy_configured ? "yes" : "no"}\n`);
  }
  if (result.observed) {
    stdout.write(`Observed: ${JSON.stringify(result.observed)}\n`);
  }
  if (result.error) {
    stdout.write(`Error: ${result.error}\n`);
  }
}

function ask(question, stdin = process.stdin, stdout = process.stdout) {
  if (!stdin.isTTY) return Promise.resolve("");
  const rl = readline.createInterface({ input: stdin, output: stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

async function addProfile(projectDir, args, streams = {}) {
  const name = firstPositional(args);
  if (!name) throw new Error("add requires a profile name");
  const proxyEnv = flagValue(args, "--proxy-env");
  const proxyUrlFlag = flagValue(args, "--proxy-url");
  let proxyUrl = proxyUrlFlag || (proxyEnv ? `\${${proxyEnv}}` : null);
  let region = flagValue(args, "--region");
  let description = flagValue(args, "--description");

  if (proxyUrl == null && (streams.stdin || process.stdin).isTTY) {
    const answer = await ask(
      `Proxy env var for ${name} (blank for ${envRefForProfile(name)}): `,
      streams.stdin || process.stdin,
      streams.stdout || process.stdout,
    );
    proxyUrl = answer ? `\${${answer}}` : envRefForProfile(name);
  }
  if (proxyUrl == null) proxyUrl = envRefForProfile(name);
  if (region == null && (streams.stdin || process.stdin).isTTY) {
    region = await ask("Region label (optional): ", streams.stdin || process.stdin, streams.stdout || process.stdout);
  }
  if (description == null && (streams.stdin || process.stdin).isTTY) {
    description = await ask("Description (optional): ", streams.stdin || process.stdin, streams.stdout || process.stdout);
  }

  egress.addOrUpdateEgressProfile(projectDir, {
    name,
    proxy_url: proxyUrl,
    region: region || null,
    description: description || null,
    enabled: !args.includes("--disabled"),
  });
  return {
    message: `Saved egress profile "${name}".`,
    profile: egress.profilePublicView(
      egress.readEgressProfilesDocument(projectDir).profiles.find((profile) => profile.name === name),
    ),
  };
}

function requestViaProfile(url, agent, timeoutMs = 5000) {
  const parsed = new URL(url);
  const requestModule = parsed.protocol === "http:" ? http : https;
  return new Promise((resolve, reject) => {
    const req = requestModule.request({
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port || undefined,
      path: `${parsed.pathname}${parsed.search}`,
      method: "GET",
      headers: { accept: "application/json,text/plain;q=0.9,*/*;q=0.1" },
      agent: agent || undefined,
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
      res.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8").slice(0, 2000);
        resolve({ status: res.statusCode || 0, headers: res.headers, body });
      });
    });
    req.on("error", reject);
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`timeout after ${timeoutMs}ms`));
    });
    req.end();
  });
}

async function testProfile(projectDir, args, env = process.env) {
  const name = firstPositional(args) || "default";
  const profile = egress.resolveEgressProfile(name, { projectRoot: projectDir, env });
  const agent = egress.createProxyAgent(profile.proxy_url);
  const testUrl = flagValue(args, "--url") || env.BOB_EGRESS_TEST_URL || "https://api.ipify.org?format=json";
  const response = await requestViaProfile(testUrl, agent);
  let observed = { status: response.status };
  try {
    const parsed = JSON.parse(response.body);
    observed = { ...observed, ...parsed };
  } catch {
    observed.body = response.body.slice(0, 200);
  }
  return {
    message: `Egress profile "${profile.name}" connectivity check completed.`,
    profile: {
      name: profile.name,
      enabled: true,
      region: profile.region,
      description: profile.description,
      proxy_configured: profile.proxy_configured,
    },
    observed,
    test_url: testUrl,
  };
}

async function execute(parsed, env = process.env, streams = {}) {
  if (parsed.command === "list") {
    return { profiles: egress.listEgressProfiles(parsed.projectDir) };
  }

  if (parsed.command === "add") {
    return addProfile(parsed.projectDir, parsed.args, streams);
  }

  if (parsed.command === "test") {
    return testProfile(parsed.projectDir, parsed.args, env);
  }

  const name = firstPositional(parsed.args);
  if (!name) throw new Error(`${parsed.command} requires a profile name`);

  if (parsed.command === "enable" || parsed.command === "disable") {
    const enabled = parsed.command === "enable";
    egress.setEgressProfileEnabled(parsed.projectDir, name, enabled);
    return { message: `${enabled ? "Enabled" : "Disabled"} egress profile "${name}".` };
  }

  if (parsed.command === "remove") {
    if (!parsed.args.includes("--yes")) {
      throw new Error(`remove requires --yes for egress profile "${name}"`);
    }
    egress.removeEgressProfile(parsed.projectDir, name);
    return { message: `Removed egress profile "${name}".` };
  }

  throw new Error(`unknown egress command: ${parsed.command}`);
}

async function main(argv = process.argv.slice(2), options = {}) {
  const env = options.env || process.env;
  const streams = {
    stdin: options.stdin || process.stdin,
    stdout: options.stdout || process.stdout,
    stderr: options.stderr || process.stderr,
  };
  const parsed = parse(argv, env);
  const result = await execute(parsed, env, streams);
  printResult(result, parsed.json, streams.stdout);
  return result;
}

function runCli(argv = process.argv.slice(2), options = {}) {
  return main(argv, options).catch((error) => {
    const message = error && error.message ? error.message : String(error);
    const stdout = options.stdout || process.stdout;
    const stderr = options.stderr || process.stderr;
    if (argv.includes("--json")) {
      stdout.write(`${JSON.stringify({ ok: false, error: message }, null, 2)}\n`);
    } else {
      stderr.write(`${message}\n`);
    }
    process.exitCode = 1;
  });
}

if (require.main === module) {
  runCli();
}

module.exports = {
  COMMANDS,
  execute,
  main,
  parse,
  requestViaProfile,
  runCli,
  usage,
};
