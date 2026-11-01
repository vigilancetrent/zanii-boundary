import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createFileProductClient } from '../src/product/client.mjs';
import { exactObject, identifier } from '../src/protocol.mjs';
import { validateProductAction } from '../src/product/policy.mjs';

export function parseAgentArguments(args) {
  const names = { '--socket': 'socketPath', '--origin': 'origin', '--token-file': 'tokenFile', '--cert-file': 'certFile', '--key-file': 'keyFile', '--ca-file': 'caFile' };
  /** @type {Record<string,string>} */
  const config = {};
  for (let i = 0; i < args.length; i += 2) {
    const name = names[args[i]];
    if (!name || !args[i + 1] || args[i + 1].startsWith('--') || config[name]) throw new Error('INVALID_AGENT_ARGUMENTS');
    config[name] = args[i + 1];
  }
  if (!config.socketPath || !config.tokenFile || !config.certFile || !config.keyFile || !config.caFile) throw new Error('AGENT_IDENTITY_ARGUMENTS_REQUIRED');
  return config;
}

export async function runAgent({ client, input = process.stdin, output = process.stdout, maxBytes = 65536 }) {
  // Each stdin line is a structured invocation; free text never becomes permission.
  async function invoke(line) {
    let response; let invocation;
    try {
      const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(line));
      exactObject(value, ['taskId', 'action']);
      invocation = { taskId: identifier(value.taskId), action: validateProductAction(value.action) };
    } catch { response = { status: 400, body: { code: 'AGENT_INVOCATION_FAILED', retryAutomatically: false } }; }
    if (invocation) {
      try { response = await client.execute(invocation.taskId, invocation.action); }
      // A lost response cannot establish whether the gateway already committed the action.
      catch { response = { status: 202, body: { code: 'AGENT_OUTCOME_UNKNOWN', operationId: invocation.action.id, state: 'unknown', retryAutomatically: false } }; }
    }
    if (!output.write(`${JSON.stringify(response)}\n`)) await new Promise((resolve) => output.once('drain', resolve));
  }
  let pending = Buffer.alloc(0);
  for await (const value of input) {
    const chunk = Buffer.from(value); let start = 0; let newline;
    while ((newline = chunk.indexOf(10, start)) !== -1) {
      if (pending.length + newline - start > maxBytes) throw new Error('AGENT_INPUT_TOO_LARGE');
      await invoke(Buffer.concat([pending, chunk.subarray(start, newline)])); pending = Buffer.alloc(0); start = newline + 1;
    }
    if (pending.length + chunk.length - start > maxBytes) throw new Error('AGENT_INPUT_TOO_LARGE');
    pending = Buffer.concat([pending, chunk.subarray(start)]);
  }
  if (pending.length) await invoke(pending);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { await runAgent({ client: createFileProductClient(parseAgentArguments(process.argv.slice(2))) }); }
  catch { process.stderr.write('AGENT_RUNNER_FAILED\n'); process.exitCode = 1; }
}
