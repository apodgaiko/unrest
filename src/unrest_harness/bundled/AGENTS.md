# Bundled asset guidance

This file adds bundled-asset rules to the root and package guidance.

- Everything below this directory is shipped as package data. Keep provider
  variants semantically aligned and verify the installed wheel can load them.
- Skills use YAML frontmatter delimited by `---`; `name` must match the skill
  directory and `description` must be non-empty. Preserve a trailing newline.
- Prompts and skills are public operational artifacts. Keep secrets, private
  source, transcripts, hidden reasoning, and host-specific absolute paths out.
- Cross-asset references must resolve. Run
  `uv run pytest -q tests/test_assets.py tests/test_documentation_contract.py`
  after edits here.
