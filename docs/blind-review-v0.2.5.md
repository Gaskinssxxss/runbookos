# Blind model-output review — v0.2.5

The export is for independent human scoring of the 18 synthetic Qwen trials from v0.2.4. It does not score predictions or invent reviewer results.

```sh
runbookos evaluation export-blind \
  reports/qwen-taxonomy-v2-20261020-repeat3/7a1ba04c-b175-42ff-bf3e-faea5c8ef411.json \
  --scenarios scenarios \
  --output-dir reports/blind-review-v024 \
  --seed 20261020
```

The command refuses to reuse an existing output directory. It writes two independently shuffled reviewer sheets, a blank adjudicator sheet, a README, and a separate `answer-key.json` with mode `0600`. Only `reviewer-1.json` and `reviewer-2.json` go to reviewers. Do not distribute the answer key until both independent reviews are complete. The reviewer sheets omit scenario IDs, trials, expected/predicted classes, and root-cause IDs. Evidence IDs are remapped to `E01`…; non-evidence model references become `UNRESOLVED-NN`. Each reviewer sees the incident context labelled untrusted, selected diagnostics, supplied evidence, model explanation, and claims.

Scores are blank. Reviewers independently score explanation accuracy, evidence support, unsupported claims, and abstention appropriateness from 0 to 2, with rationale. The adjudicator sheet is for resolving disagreements after both sheets are complete. The existing rubric and adjudication guidance are in [diagnostic taxonomy v2](diagnostic-taxonomy-v2.md).

After reviewers return completed sheets, agreement can be calculated without opening the answer key:

```sh
runbookos evaluation review-agreement \
  reports/blind-review-v024/reviewer-1.json \
  reports/blind-review-v024/reviewer-2.json
```

This reports exact agreement and unweighted Cohen's kappa for each rubric dimension. If either score distribution makes kappa undefined, the output is `null`; exact agreement remains available. Do not interpret agreement as accuracy. Only after agreement and adjudication are recorded may an evaluator compare reviewer scores with the withheld benchmark key.

The v0.2.4 dataset retained parsed structured predictions and explanations but did not persist the provider's exact response text. The packet therefore reviews the exact stored explanation/claim content; it does not claim to reconstruct full raw provider response bytes. Starting with v0.2.5, new benchmark trials retain each provider response separately from verified evidence references.
