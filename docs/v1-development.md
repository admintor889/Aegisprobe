# v1 Development Notes

This version intentionally implements only the generic Codex-like terminal-agent foundation. Security and penetration-testing capabilities are deferred until later requirements are provided.

- Codex-like `chat` and `run` commands.
- DeepSeek/OpenAI-compatible provider.
- SQLite audit trail.
- Human approval before every shell command.
- Local file path context loading.
- Natural-language intent extraction before task execution.
- Placeholder interfaces for Skills and MCP.

## Codex-like Task Flow

The v1 execution model mirrors Codex at the architecture level:

1. A session receives natural-language user input.
2. The assistant extracts intent, URL/domain targets, local file paths, and constraints.
3. A turn is created and persisted.
4. Context is assembled from the extracted target and optional local files.
5. The model is sampled for a structured decision.
6. The decision may emit assistant text, a plan, or a tool action.
7. Tool actions are routed through policy and explicit approval.
8. Tool observations are stored and fed into the next decision iteration.
9. The turn completes when the model/fallback decision has no more tool actions, or it returns `needs_input`.

CLI task execution wraps this in a higher-level task loop: after the user submits a task, the assistant continues running turns automatically until completion, safety limit, or a required user answer.

This keeps the implementation extensible for future ToolRouter, Skill, MCP, and multi-agent support without making v1 a full scanner.

Out of scope for v1:

- Automated vulnerability scanning.
- Markdown/HTML report generation.
- Executing existing `skills/**/*.yaml`.
- Full MCP server implementation.
- Security tool orchestration.
