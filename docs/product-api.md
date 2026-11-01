# Product API

The HTTPS server has distinct gateway and resource roles. Use the product client with explicit CA, certificate, key and token files; do not disable certificate verification. A caller needs the required scopes, role, tenant and task ownership. Configuring a client does not provision a task or start a gateway.

## Gateway routes

| Method | Route | Purpose |
| --- | --- | --- |
| POST | `/v1/tasks` | Operator task creation; requires `runtime:admin`. |
| GET | `/v1/tasks/:id` | Read an authorized task; requires `runtime:read`. |
| POST | `/v1/tasks/:id/delegate` | Create a narrower child task; requires `runtime:invoke`. |
| POST | `/v1/tasks/:id/revoke` | Revoke task authority; requires `runtime:invoke` and policy authorization. |
| POST | `/v1/approvals` | Approve an exact action with an expiry; requires `runtime:approve` and an operator/approver role. |
| POST | `/v1/actions` | Execute a permitted action; requires `runtime:invoke` and an agent/operator role. |
| GET | `/v1/operations/:id` | Inspect a task-owned operation. |
| POST | `/v1/operations/:id/reconcile` | Reconcile an uncertain provider outcome. |
| POST | `/v1/operations/:id/cancel` | Request cancellation subject to operation-state rules. |

These are the primary workflow routes, not a complete endpoint inventory. Evidence, memory, operations and protocol handlers have separate permissions. Exact schemas and role checks are defined in `src/product/server.mjs` and `src/product/policy.mjs`.

## Action request

`POST /v1/actions` accepts a task identifier and a validated action:

```json
{
  "taskId": "task-id",
  "action": {
    "id": "operation-id",
    "kind": "read",
    "documentId": "policy"
  }
}
```

Use the same operation ID when checking or reconciling the same work. Do not generate a new ID to retry an unknown effect. A conflicting reuse fails instead of changing an already reserved operation.

The executor returns the operation ID and state. Completed responses may include a result; content release still requires current authority. A response can remain pending or report a failed/unknown outcome. The internal document service's sharing effect is mailbox delivery, not external email.

## Resource and protocol boundaries

Resource endpoints under `/v1/resource/` are service-to-service interfaces, not an agent bypass. Resource execution verifies the configured identity and grant, provider revision, deadline and operation state independently.

Configured MCP traffic uses `/mcp`; A2A uses `/a2a` and its agent-card route. The adapters do not make unsupported tools safe automatically. See [adapter contracts](adapter-ports.md) and [architecture](product-architecture.md).

## Client exports

`@zanii/boundary` and `@zanii/boundary/client` export the product client. `@zanii/boundary/evidence` exports product evidence verification. Research-only interfaces are separated under `./research/client` and `./research/evidence`.

The repository remains private to npm publication through `package.json`; public GitHub visibility does not publish an npm package. See the [README example](../README.md#client-example).
