# Spike: one blueprint → one agent identity → one token

**Goal:** confirm by hand the autonomous-agent token flow that ADR-003's blast-radius argument depends on, and record exactly what worked. Run this only if probe W01–W03 are **OK**, and only after confirming the Graph writes in the session (CLAUDE.md §14.1).

Source of the expected flow: Microsoft Learn, *Request agent tokens for autonomous agents* and *Create an agent identity blueprint* (read 2026-10-31).

## Run it
The steps below are automated in `scripts/spike_agent_token.py`, since step 5 needs a signed JWT that's impractical to make by hand:
```powershell
uv run python scripts/spike_agent_token.py --sponsor YOUR-UPN             # prints the plan
uv run python scripts/spike_agent_token.py --sponsor YOUR-UPN --execute   # runs it, asks first
```
It writes `docs/spikes/agent-id-token-spike-results.md` (claims only, IDs labelled or redacted) and adds one check the manual steps don't have: **can a T1 minted for agent A be used to become agent B?**

## Steps (what the script does; as `nhigov-provisioner`, Graph v1.0)

1. **Blueprint**
   `POST /applications` `{"@odata.type":"Microsoft.Graph.AgentIdentityBlueprint","displayName":"bp-spike","sponsors@odata.bind":["https://graph.microsoft.com/v1.0/users/<paul-oid>"]}`
   Record `id` (object ID) and `appId`.
2. **Blueprint principal**
   `POST /servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal` `{"appId":"<bp appId>"}`
3. **Certificate on the blueprint** (no secret; P7)
   `nhigov cert new bp-spike --days 7`, then
   `PATCH /applications/<bp id>` `{"keyCredentials":[{"type":"AsymmetricX509Cert","usage":"Verify","key":"<base64 DER of bp-spike.cer>"}]}`
   (`addKey` needs a proof signed by an *existing* key, so the first key goes on with PATCH.)
4. **Agent identity**
   `POST /servicePrincipals/microsoft.graph.agentIdentity` `{"displayName":"nhi-spike","agentIdentityBlueprintId":"<bp appId>","sponsors@odata.bind":[…]}`
   Record `id` and `appId`. **Are they the same value?**
5. **Token 1: blueprint, for the exchange**
   `POST https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`
   `client_id=<bp appId>` · `scope=api://AzureADTokenExchange/.default` · `fmi_path=<agent identity appId>` · `grant_type=client_credentials` · `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` · `client_assertion=<JWT signed with bp-spike.pem>`
6. **Token 2: agent identity, for a resource**
   Same endpoint: `client_id=<agent identity appId>` · `scope=https://graph.microsoft.com/.default` · `grant_type=client_credentials` · `client_assertion_type=…jwt-bearer` · `client_assertion=<token 1>`
7. **Decode both tokens** (jwt.ms, or locally) and record the claims below.
8. **Blast-radius test:** create a *second* agent identity under the same blueprint and repeat steps 5–6 with its appId in `fmi_path`. Expected: it succeeds using the **same blueprint certificate**.
9. **Clean up:** `DELETE /applications/<bp id>` (cascades to agent identities). Delete `~/.nhigov/certs/bp-spike.*`.

## Results (run 2026-10-31, full output in `agent-id-token-spike-results.md`)

| Question | Answer |
|---|---|
| Blueprint create on Free tenant worked? | Yes |
| Certificate upload to blueprint | `PATCH …/microsoft.graph.agentIdentityBlueprint` with `keyCredentials` worked (documented path) |
| Agent identity `id` == `appId`? | Yes |
| Token 1 claims | `oid` = blueprint principal, `azp` = blueprint appId, `sub` = `/eid1/c/pub/t/<tenant>/a/<bp appId>/<agent id>`, `idtyp` = app |
| Token 2 claims | `appid` = `oid` = `sub` = agent identity, `idtyp` = app, includes `xms_par_app_azp` |
| Which `oid` appears in token 2? | **The agent identity** |
| Step 8: second agent's token from the same blueprint cert? | **Yes**: blast radius confirmed |
| T1 for agent A reused to become agent B? | **Refused** (`AADSTS7002142`): T1 is bound to one agent |
| Any permission needed beyond ADR-005's list? | No |
| Surprises | Agent creation needed retries (~15s replication lag). **Blueprint delete did not cascade** to agent identities; deleted them explicitly. |

If anything differs from ADR-003, stop, record it in `docs/learning-notes.md`, and propose an ADR change (CLAUDE.md §14.7).
