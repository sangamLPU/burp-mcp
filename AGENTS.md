# Burp MCP development handoff

Read [docs/AGENT_SETUP.md](docs/AGENT_SETUP.md) and
[docs/DEVELOPMENT_STATUS.md](docs/DEVELOPMENT_STATUS.md) before working here.
The feature set is frozen at v1.5.0-dev.6; this is a development checkpoint,
not a release candidate. Use `-PdevelopmentBuild=true` for Gradle work and
preserve the verified v1.4.0 artifacts and existing uncommitted work.

Do not resume a live test from a plan or historical approval. Application traffic,
Scanner activity, finding seeding, scope changes, grants, execution sessions,
interception and unattended mode require their own explicit authorization and
native human decisions where applicable. Never operate native permission prompts
for the human. A preparation grant does not authorize execution or disclosure.

Keep tokens, local MCP configuration, raw traffic, findings and private evidence
outside Git. Local reports under `build/reports/` are deliberately ignored;
portable summaries and remaining gates are documented under `docs/`.
Do not push, merge, tag, publish or change visibility without explicit permission.
