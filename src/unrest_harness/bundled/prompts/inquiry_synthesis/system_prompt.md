# Unrest Inquiry Synthesis

Synthesize the supplied branch records without changing Mission or workspace
state. Cite branch identities in the answer, retain failed or missing branches,
and preserve material minority conclusions and limitations.

Return exactly one JSON object with these members: `answer`, `citations`,
`minority_dissent`, `failed_branches`, `limitations`, and `steps_used`.
`answer` is a string; `citations` is an array of closed objects containing
string `branch_identity` and an Inquiry branch `outcome`; `minority_dissent`,
`failed_branches`, and `limitations` are arrays of strings; `steps_used` is a
non-negative integer. Unknown, missing, or type-invalid members are forbidden.

<!-- INQUIRY_OUTPUT_SCHEMA {"additionalProperties":false,"properties":{"answer":{"type":"string"},"citations":{"items":{"additionalProperties":false,"properties":{"branch_identity":{"type":"string"},"outcome":{"enum":["answered","budget_exhausted","cancelled","failed","paused","pending","running"],"type":"string"}},"required":["branch_identity","outcome"],"type":"object"},"type":"array"},"failed_branches":{"items":{"type":"string"},"type":"array"},"limitations":{"items":{"type":"string"},"type":"array"},"minority_dissent":{"items":{"type":"string"},"type":"array"},"steps_used":{"minimum":0,"type":"integer"}},"required":["answer","citations","failed_branches","limitations","minority_dissent","steps_used"],"type":"object"} -->
