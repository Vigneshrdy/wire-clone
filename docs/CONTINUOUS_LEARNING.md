# Continuous learning

## The rule that shapes everything else

```
live network traffic  ->  automatic retraining  ->  automatic production replacement
```

is **never implemented**. That chain is a poisoning path: an attacker who can
influence the monitored network can influence the training data, and therefore the
production model.

Production data may become a *training candidate*. To influence production it must
pass, in order: validation → analyst labelling → dataset building → training →
evaluation → governance gates → explicit promotion.

No code path violates this. `train_dga` registers as `CANDIDATE` and never
promotes. Drift detection emits `DriftEvent` records and calls nothing. Shadow
comparison is read-only. Promotion happens only through
`POST /api/v1/models/{detector}/promote` or `sih-ntd models promote` — both of which
run the gates first.

## Pipeline

```
ALERTS
  |
  v
ANALYST FEEDBACK STORE                  POST /api/v1/feedback
  TRUE_POSITIVE / FALSE_POSITIVE / FALSE_NEGATIVE / UNCERTAIN
  + corrected_threat_class, analyst_id, confidence, notes, timestamp
  Response says so explicitly: "training candidate only; production models unchanged"
  |
  v
DATA QUALITY + DRIFT ENGINE             sih_ntd/ml/drift.py
  feature distribution   PSI (continuous, quantile-binned) / JS (categorical)
  prediction + confidence distribution   PSI on stored scores
  class distribution     JS divergence
  label performance      precision decay from analyst feedback
  -> DriftEvent { detector, model_version, feature, drift_type, metric, score,
                  threshold, window, sizes, recommendation }
  SIGNAL ONLY. Never retrains, never deploys.
  |
  v
TRAINING DATA FACTORY                   sih_ntd/ml/dataset.py
  build_dga_dataset       lab-generated (offline fallback, see caveat below)
  build_feedback_dataset  analyst-reviewed labels joined to the feature values the
                          verdict actually used (from alert evidence, not a later
                          recomputation)
  records dataset_id, created_at, feature_schema_version, source summary,
  class distribution, split strategy, split sizes, feature names,
  label provenance, SHA-256 content hash, row count, seed
  |
  v
OFFLINE TRAINING                        sih_ntd/ml/training.py
  fixed seed; HistGradientBoosting + isotonic calibration on a held-out split
  metrics: precision, recall, F1, PR-AUC, ROC-AUC, confusion matrix, FPR, FNR,
           Brier score (calibration), MEASURED single-row inference latency
  plus out-of-family and out-of-corpus transfer metrics
  registers as CANDIDATE
  |
  v
CHAMPION vs CHALLENGER                  sih_ntd/ml/shadow.py
  challenger scores the same feature vectors as champion
  results persisted with shadow=1, dropped by fusion, never alert
  compare() reports held-out metrics + live score-distribution PSI
  |
  v
GOVERNANCE GATES                        sih_ntd/ml/governance.py
  |
  v
MODEL + FEATURE REGISTRY                sih_ntd/ml/registry.py
  |
  v
EXPLICIT PROMOTION  (reversible)
```

## Leakage control

Splits are by **generator family and by time**, never a random row shuffle.

- `build_dga_dataset` — stratified 70/15/15 within each training family, plus one
  DGA family excluded from training entirely and scored separately as
  `unseen_family`.
- `build_feedback_dataset` — temporal 70/15/15 by alert timestamp. A model that only
  works on data from before its own training window is not useful.

Feature generation is shared: `features/stats.py` and `features/engine.py` produce
both training rows and inference rows. Changing a feature requires bumping
`FEATURE_SCHEMA_VERSION`, and the registry then refuses to load any model trained
against the old one (`SchemaVersionMismatch`) rather than silently mis-feeding it.

## Governance gates

`PromotionGate.evaluate` — all must pass, or be explicitly acknowledged:

| Gate | Default requirement |
|---|---|
| `precision` | ≥ 0.90 |
| `recall` | ≥ 0.80 |
| `false_positive_rate` | ≤ 0.02 |
| `inference_latency` | ≤ 5 ms per single-row call, measured |
| `feature_schema` | matches the running `FEATURE_SCHEMA_VERSION` |
| `artifact_integrity` | 64-hex SHA-256 recorded |
| `dataset_recorded` | a `dataset_id` exists |
| `regression_tests` | passed, when supplied by the caller |
| `improves_on_champion` | candidate F1 ≥ champion F1 |
| `generalises_to_independent_generator` | ≥ 50 % recall on out-of-corpus probe names |
| `independent_benign_fpr` | ≤ 5 × the allowed FPR on out-of-corpus benign names |
| `not_implausibly_perfect` | precision and recall are not both exactly 1.0 |

The last three exist because of a real failure in this repository. A DGA model
scored 1.000 precision and recall on its own held-out split and then assigned
probability 0.000 to every obviously-random name from a different generator: it had
memorised its training generators. In-distribution metrics could not see that; the
transfer gate can. Details in [DETECTORS.md](DETECTORS.md#dga).

### Acknowledged overrides

A gate can be accepted as failing:

```bash
uv run sih-ntd models promote dga --model-version 20260905-1 \
  --acknowledge not_implausibly_perfect \
  --reason "lab demo: corpus is synthetic and separable by construction"
```

`--reason` is mandatory when acknowledging. The override is written into
`promotions.jsonl` as `acknowledged:<gate> = false` and stays visible forever. This
is how "we knew and decided anyway" remains auditable instead of becoming folklore.

## Registry

```
ml_artifacts/<detector>/models/<model_version>.json      ModelMetadata
ml_artifacts/<detector>/models/<model_version>.joblib    the artefact
ml_artifacts/<detector>/promotions.jsonl                 append-only audit log
ml_artifacts/datasets/<dataset_id>/{train,validation,test,unseen_family}.csv
ml_artifacts/datasets/<dataset_id>/metadata.json
```

Statuses: `CANDIDATE` → `CHALLENGER` → `CHAMPION` → `RETIRED` / `REJECTED`.

Promoting to `CHAMPION` retires the incumbent and records `previous_champion`, so
`rollback()` restores it without guessing. Every transition appends a
`PromotionRecord` with actor, reason and gate results.

### Artifact safety

`joblib.load` executes pickle opcodes, so it is only ever called on a file whose
SHA-256 matches the hash recorded when *this system* produced it, and the loaded
object's class name is checked against the recorded `estimator_class`. Anything else
raises `ArtifactIntegrityError`. Tested for both tampering and substitution.

Models are loaded once at worker startup, not hot-reloaded: swapping a model under
a running pipeline would make alerts non-reproducible mid-stream. Promotion is
followed by a worker restart.

## Threat intelligence

External intelligence (CISA/CERT/CVE/MISP/fingerprint lists) is **data**, never
instructions. `ThreatIntelIndicator` normalises and validates it and records
provenance and a `reviewed` flag. It cannot execute code, change configuration,
promote a model, or alter a detection rule without review.

## Operating loop

```bash
# 1. see what the models are doing
curl -s localhost:8000/api/v1/model-health | jq

# 2. look for drift between stored feature windows
uv run sih-ntd drift --detector dga --entity-kind HOST

# 3. label some alerts
curl -sX POST localhost:8000/api/v1/feedback \
  -H 'content-type: application/json' \
  -d '{"alert_id":"...","label":"FALSE_POSITIVE","analyst_id":"you","notes":"backup job"}'

# 4. train a candidate (never promotes)
uv run sih-ntd train-dga

# 5. run the gates and the shadow comparison
uv run sih-ntd models evaluate dga

# 6. promote deliberately, then restart workers
uv run sih-ntd models promote dga --model-version <v> --reason "beats champion on F1 and FPR"

# 7. if it misbehaves
uv run sih-ntd models rollback dga
```
