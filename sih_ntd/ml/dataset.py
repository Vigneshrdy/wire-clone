"""Training data factory.

Builds versioned, hashed datasets with recorded provenance. Two sources:

1. **Lab-generated DGA/benign domains** (:func:`build_dga_dataset`). No labelled
   corpus ships with this repository and there is no network access, so the
   initial DGA training set is synthesised from a seeded benign-name generator and
   four DGA family generators. Every metric produced from it is explicitly labelled
   as lab data -- it is *not* evidence of field performance, and
   ``docs/CONTINUOUS_LEARNING.md`` says so.
2. **Analyst-reviewed feedback plus stored feature history**
   (:func:`build_feedback_dataset`). This is the path a deployment actually uses:
   alerts an analyst labelled, joined to the feature vectors that produced them.

Leakage control
---------------
Splits are by **generator family / scenario and by time**, never a random row
shuffle. Random splitting on generated data puts near-duplicate names from the
same family on both sides of the split and reports a precision that does not
survive contact with a new family.
"""

from __future__ import annotations

import csv
import hashlib
import json
import random
import string
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence

from ..config import Settings, get_settings
from ..features.stats import DNS_LEXICAL_FEATURES, dns_lexical_features
from ..schemas import FEATURE_SCHEMA_VERSION, DatasetMetadata, FeedbackLabel
from ..store import Store

# --- benign name synthesis -------------------------------------------------
# Deliberately small and readable: pronounceable, dictionary-ish labels with the
# hyphens, digits and brand-ish concatenations that real domains have. A real
# deployment should replace this with a genuine benign corpus (e.g. a Tranco
# snapshot) -- see docs/CONTINUOUS_LEARNING.md.
WORDS = (
    "cloud data mail news shop store bank pay health learn media music video photo "
    "travel hotel food green solar auto parts tools home smart secure trust group "
    "global north south east west first prime next open live share connect link "
    "point line stack cache edge node core base craft works labs studio design "
    "print paper wood metal stone river lake hill park city town village market "
    "fresh daily weekly super mega ultra micro nano tele radio press books toys "
    "sports fitness yoga dental clinic pharma legal advice finance invest capital"
).split()
TLDS = ("com", "net", "org", "io", "co", "in", "info", "biz", "dev", "app")
SUBS = ("www", "api", "cdn", "mail", "static", "img", "login", "shop", "blog", "m")


MACHINE_ZONES = (
    "cdn.example.com", "assets.example.net", "compute.example-cloud.com",
    "internal.example.org", "edge.example-cdn.net", "static.example.io",
    "storage.example-cloud.net", "telemetry.example.com",
)


#: Alphabets that machine-generated labels are drawn from, benign or malicious.
#: Both classes sample from the same set, because in reality both do: a CDN asset
#: hash and a hash-based DGA label are the same kind of string.
RANDOM_ALPHABETS: dict[str, str] = {
    "letters": string.ascii_lowercase,
    "alphanum": string.ascii_lowercase + string.digits,
    "digit_heavy": string.ascii_lowercase + string.digits * 3,
    "hex": "0123456789abcdef",
    "base32": "abcdefghijklmnopqrstuvwxyz234567",
    "consonant": "bcdfghjklmnpqrstvwxz" * 3 + "aeiou",
}


def _random_label(rng: random.Random, alphabet: str | None = None) -> str:
    """A machine-generated label with randomised alphabet and length.

    Randomising the *generator hyperparameters* per sample, rather than emitting
    one fixed shape per family, is what stops a classifier from recovering
    "which generator wrote this" instead of "is this random". An earlier version
    used fixed per-family shapes; the resulting model scored a perfect 1.0 on the
    lab test split and then returned probability 0.0 for obviously random names
    produced by a *different* generator. Measured, not assumed -- that is why this
    function exists.
    """
    alphabet = alphabet or RANDOM_ALPHABETS[rng.choice(list(RANDOM_ALPHABETS))]
    length = rng.randint(8, 32)
    return "".join(rng.choice(alphabet) for _ in range(length))


def _benign_machine_domain(rng: random.Random) -> str:
    """A *legitimate* machine-generated name.

    Real benign DNS is full of these: CDN asset hashes, cloud instance names,
    Kubernetes service names, tracking tokens. They are long, high-entropy and
    digit-heavy -- lexically almost indistinguishable from a DGA, which is exactly
    why DGA detectors produce false positives in the field.

    An earlier version of this generator emitted only dictionary-style benign names.
    The model then scored precision=recall=1.0, the promotion gate flagged it as
    implausible, and it was right: the dataset was trivially separable and the
    number meant nothing. These rows are what make the metric real.
    """
    style = rng.random()
    zone = rng.choice(MACHINE_ZONES)
    if style < 0.25:
        # Cloud instance names: structured, not random.
        label = f"ec2-{'-'.join(str(rng.randint(1, 254)) for _ in range(4))}"
    elif style < 0.45:
        label = f"{rng.choice(WORDS)}-{_random_label(rng, RANDOM_ALPHABETS['hex'])[:10]}"
    else:
        # Genuinely random benign labels, from the SAME sampler the DGA families
        # use. This creates deliberate, irreducible overlap between the classes:
        # the model must pay for it in precision, which is exactly what happens in
        # the field and what makes the reported number worth reading.
        label = _random_label(rng)
    return f"{label}.{zone}" if rng.random() < 0.6 else _attach_zone(rng, label)


def _benign_domain(rng: random.Random) -> str:
    """A plausible benign name: mostly human-registered, some machine-generated.

    The machine-generated share is deliberately large (~28%) because that is what
    makes the DGA task non-trivial and the reported precision meaningful.
    """
    if rng.random() < 0.28:
        return _benign_machine_domain(rng)
    style = rng.random()
    if style < 0.35:
        label = rng.choice(WORDS) + rng.choice(WORDS)
    elif style < 0.55:
        label = f"{rng.choice(WORDS)}-{rng.choice(WORDS)}"
    elif style < 0.7:
        label = rng.choice(WORDS) + str(rng.randint(1, 999))
    elif style < 0.85:
        label = rng.choice(WORDS)
    else:
        label = rng.choice(WORDS) + rng.choice(WORDS) + rng.choice(WORDS)
    name = f"{label}.{rng.choice(TLDS)}"
    if rng.random() < 0.4:
        name = f"{rng.choice(SUBS)}.{name}"
    return name


# --- DGA family synthesis --------------------------------------------------
# Four families with genuinely different lexical signatures, so a split by family
# measures generalisation to an unseen algorithm rather than memorisation.


def _attach_zone(rng: random.Random, label: str) -> str:
    """Attach a parent zone to a generated label.

    Used by BOTH the benign machine-name generator and every DGA family, and this
    matters: an earlier version gave DGA names a bare ``label.tld`` shape while
    benign machine names sat under multi-label CDN zones. The classifier then
    separated the classes perfectly on ``dns_label_count`` alone -- a structural
    artefact of the generators, not a lexical signal. Sharing this function forces
    the two classes to differ only in the randomness of the label itself, which is
    the thing the model is supposed to learn.
    """
    style = rng.random()
    if style < 0.45:
        return f"{label}.{rng.choice(TLDS)}"
    if style < 0.7:
        return f"{label}.{rng.choice(WORDS)}{rng.choice(WORDS)}.{rng.choice(TLDS)}"
    return f"{label}.{rng.choice(MACHINE_ZONES)}"


def _dga_uniform(rng: random.Random) -> str:
    """Conficker-style: uniform random lowercase letters."""
    return _attach_zone(rng, _random_label(rng, RANDOM_ALPHABETS["letters"]))


def _dga_hex(rng: random.Random) -> str:
    """Hash-based: hexadecimal labels."""
    return _attach_zone(rng, _random_label(rng, RANDOM_ALPHABETS["hex"]))


def _dga_alphanum(rng: random.Random) -> str:
    """Mixed alphanumeric with a high digit ratio."""
    return _attach_zone(rng, _random_label(rng, RANDOM_ALPHABETS["digit_heavy"]))


def _dga_consonant(rng: random.Random) -> str:
    """Consonant-heavy names: low vowel ratio, long consonant runs."""
    return _attach_zone(rng, _random_label(rng, RANDOM_ALPHABETS["consonant"]))


def _dga_base32(rng: random.Random) -> str:
    """Encoded-payload style: base32 alphabet."""
    return _attach_zone(rng, _random_label(rng, RANDOM_ALPHABETS["base32"]))


def _dga_dictionary(rng: random.Random) -> str:
    """Matsnu/suppobox style: real words concatenated.

    The known-hard case for any purely lexical model: entropy, digit ratio and
    vowel ratio all look like a legitimately registered name. It is the designated
    unseen-family holdout precisely because it is where this approach is weakest,
    and pretending otherwise would be the dishonest option.
    """
    return _attach_zone(rng, "".join(rng.choice(WORDS) for _ in range(rng.randint(2, 4))))


DGA_FAMILIES: dict[str, Callable[[random.Random], str]] = {
    "uniform": _dga_uniform,
    "hex": _dga_hex,
    "alphanum": _dga_alphanum,
    "consonant": _dga_consonant,
    "base32": _dga_base32,
    "dictionary": _dga_dictionary,
}

#: Family excluded from training entirely and scored separately, so the model card
#: reports out-of-family generalisation instead of hiding it.
HOLDOUT_FAMILY = "dictionary"


@dataclass
class Dataset:
    """An in-memory dataset plus its metadata, already split."""

    metadata: DatasetMetadata
    feature_names: list[str]
    train: tuple[list[list[float]], list[int]]
    validation: tuple[list[list[float]], list[int]]
    test: tuple[list[list[float]], list[int]]
    #: Human-readable provenance for each split (family/scenario names).
    split_provenance: dict[str, list[str]]
    #: Optional extra set drawn from a DGA family never seen in training, plus
    #: benign names, used to report out-of-family generalisation separately.
    unseen_family: tuple[list[list[float]], list[int]] | None = None

    def sizes(self) -> dict[str, int]:
        sizes = {
            "train": len(self.train[1]),
            "validation": len(self.validation[1]),
            "test": len(self.test[1]),
        }
        if self.unseen_family is not None:
            sizes["unseen_family"] = len(self.unseen_family[1])
        return sizes


def _content_hash(rows: Sequence[tuple[str, int]]) -> str:
    digest = hashlib.sha256()
    for name, label in rows:
        digest.update(f"{name}|{label}\n".encode())
    return digest.hexdigest()


def build_dga_dataset(
    *, seed: int = 20260905, per_family: int = 3000, benign_count: int = 12000
) -> Dataset:
    """Lab-generated DGA dataset with two complementary evaluation sets.

    * ``train``/``validation``/``test`` are stratified 70/15/15 across the five
      *training* families and the benign names. The test split is the primary
      evaluation set: unseen samples from the distribution the model is meant to
      serve.
    * ``unseen_family`` holds :data:`HOLDOUT_FAMILY`, excluded from training
      entirely, and is scored separately.

    An earlier version split by family alone (train on 2, test on a 3rd). It
    measured only out-of-family transfer, reported ROC-AUC 0.50, and produced no
    usable model -- the right answer to which is to train on a diverse family set
    *and* report the transfer number, not to pick whichever split flatters the
    model.
    """
    rng = random.Random(seed)
    benign = [_benign_domain(rng) for _ in range(benign_count)]
    families = {
        name: [builder(random.Random(seed + index)) for _ in range(per_family)]
        for index, (name, builder) in enumerate(DGA_FAMILIES.items())
    }
    holdout = families.pop(HOLDOUT_FAMILY)
    training_families = list(families)

    def split_three(items: list[str]) -> tuple[list[str], list[str], list[str]]:
        first, second = int(len(items) * 0.7), int(len(items) * 0.85)
        return items[:first], items[first:second], items[second:]

    dga_train: list[str] = []
    dga_val: list[str] = []
    dga_test: list[str] = []
    for name in training_families:
        a, b, c = split_three(families[name])
        dga_train += a
        dga_val += b
        dga_test += c
    b_train, b_val, b_test = split_three(benign)

    def pack(positives: list[str], negatives: list[str]) -> tuple[list[list[float]], list[int]]:
        rows: list[list[float]] = []
        labels: list[int] = []
        for domain in positives:
            rows.append([dns_lexical_features(domain)[name] for name in DNS_LEXICAL_FEATURES])
            labels.append(1)
        for domain in negatives:
            rows.append([dns_lexical_features(domain)[name] for name in DNS_LEXICAL_FEATURES])
            labels.append(0)
        return rows, labels

    train = pack(dga_train, b_train)
    validation = pack(dga_val, b_val)
    test = pack(dga_test, b_test)
    # Unseen-family set is scored against the same benign test names, so its
    # precision is comparable to the primary test precision.
    unseen = pack(holdout, b_test)

    all_rows = (
        [(d, 1) for name in training_families for d in families[name]]
        + [(d, 1) for d in holdout]
        + [(d, 0) for d in benign]
    )
    dataset_id = f"dga-lab-{seed}-{len(all_rows)}"
    metadata = DatasetMetadata(
        dataset_id=dataset_id,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        detector="dga",
        source_summary={
            "synthetic_benign": benign_count,
            "synthetic_dga": per_family * len(DGA_FAMILIES),
            "dga_families_trained": len(training_families),
            "dga_families_held_out": 1,
        },
        class_distribution={
            "dga": per_family * len(DGA_FAMILIES), "benign": benign_count
        },
        split_strategy=(
            "stratified 70/15/15 within each of "
            f"{len(training_families)} DGA families ({', '.join(training_families)}) and "
            f"benign names; family '{HOLDOUT_FAMILY}' excluded from training and "
            "scored separately as unseen_family"
        ),
        split_sizes={
            "train": len(train[1]), "validation": len(validation[1]),
            "test": len(test[1]), "unseen_family": len(unseen[1]),
        },
        feature_names=list(DNS_LEXICAL_FEATURES),
        label_provenance={"lab_generated": len(all_rows)},
        content_hash=_content_hash(all_rows),
        row_count=len(all_rows),
        seed=seed,
    )
    return Dataset(
        metadata=metadata,
        feature_names=list(DNS_LEXICAL_FEATURES),
        train=train,
        validation=validation,
        test=test,
        split_provenance={
            "train": training_families,
            "validation": training_families,
            "test": training_families,
            "unseen_family": [HOLDOUT_FAMILY],
        },
        unseen_family=unseen,
    )


def build_feedback_dataset(
    store: Store,
    detector: str,
    *,
    feature_names: Sequence[str],
    entity_kind: str | None = None,
    window_seconds: float | None = None,
    settings: Settings | None = None,
) -> Dataset | None:
    """Dataset from analyst-reviewed labels joined to stored feature vectors.

    This is the production continuous-learning path. Note what it does *not* do:
    it does not label anything itself, it does not use detector output as ground
    truth, and it does not touch a champion model. It produces a dataset that a
    human then trains and evaluates -- see docs/CONTINUOUS_LEARNING.md.

    Split is temporal (oldest 70% train, next 15% validation, newest 15% test)
    because a model that only works on data from before its own training window is
    not useful.
    """
    settings = settings or get_settings()
    feedback = store.query_feedback(limit=100_000)
    usable = [
        row for row in feedback
        if row["label"] in (FeedbackLabel.TRUE_POSITIVE, FeedbackLabel.FALSE_POSITIVE)
    ]
    if not usable:
        return None

    alerts = {row["alert_id"]: row for row in usable}
    rows: list[tuple[float, list[float], int, str]] = []
    for alert_id, row in alerts.items():
        alert = store.get_alert(alert_id)
        if alert is None or alert.detector_name != detector:
            continue
        # The alert's own evidence holds the feature values the verdict used, so
        # the label is joined to exactly those numbers -- not to a later
        # re-computation that may differ.
        observations = {**alert.evidence.observations, **alert.evidence.baseline_comparisons}
        if not all(name in observations for name in feature_names):
            continue
        label = 1 if row["label"] == FeedbackLabel.TRUE_POSITIVE else 0
        rows.append((alert.timestamp.timestamp(), [observations[n] for n in feature_names], label, alert_id))

    if len(rows) < 20:
        return None
    rows.sort(key=lambda item: item[0])
    train_end = int(len(rows) * 0.7)
    val_end = int(len(rows) * 0.85)

    def pack(subset: list[tuple[float, list[float], int, str]]) -> tuple[list[list[float]], list[int]]:
        return [item[1] for item in subset], [item[2] for item in subset]

    train, validation, test = (
        pack(rows[:train_end]), pack(rows[train_end:val_end]), pack(rows[val_end:])
    )
    positives = sum(1 for item in rows if item[2] == 1)
    dataset_id = f"{detector}-feedback-{int(rows[0][0])}-{len(rows)}"
    metadata = DatasetMetadata(
        dataset_id=dataset_id,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        detector=detector,
        source_summary={"analyst_feedback": len(rows)},
        class_distribution={"true_positive": positives, "false_positive": len(rows) - positives},
        split_strategy="temporal (70/15/15 by alert timestamp)",
        split_sizes={"train": len(train[1]), "validation": len(validation[1]), "test": len(test[1])},
        feature_names=list(feature_names),
        label_provenance={"analyst_reviewed": len(rows)},
        content_hash=_content_hash([(item[3], item[2]) for item in rows]),
        row_count=len(rows),
    )
    store.mark_feedback_consumed([row["feedback_id"] for row in usable], dataset_id)
    return Dataset(
        metadata=metadata, feature_names=list(feature_names), train=train,
        validation=validation, test=test,
        split_provenance={"train": ["oldest"], "validation": ["middle"], "test": ["newest"]},
    )


def save_dataset(dataset: Dataset, root: Path | str | None = None) -> Path:
    """Persist a dataset next to the model registry so a run is reproducible."""
    root = Path(root or get_settings().registry.root) / "datasets" / dataset.metadata.dataset_id
    root.mkdir(parents=True, exist_ok=True)
    splits = [("train", dataset.train), ("validation", dataset.validation), ("test", dataset.test)]
    if dataset.unseen_family is not None:
        splits.append(("unseen_family", dataset.unseen_family))
    for split, (rows, labels) in splits:
        with (root / f"{split}.csv").open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow([*dataset.feature_names, "label"])
            writer.writerows([[*row, label] for row, label in zip(rows, labels)])
    (root / "metadata.json").write_text(dataset.metadata.model_dump_json(indent=2))
    (root / "split_provenance.json").write_text(json.dumps(dataset.split_provenance, indent=2))
    return root


def load_dataset_metadata(dataset_id: str, root: Path | str | None = None) -> DatasetMetadata | None:
    path = Path(root or get_settings().registry.root) / "datasets" / dataset_id / "metadata.json"
    if not path.exists():
        return None
    return DatasetMetadata.model_validate_json(path.read_text())


def iter_dataset_ids(root: Path | str | None = None) -> Iterable[str]:
    base = Path(root or get_settings().registry.root) / "datasets"
    if not base.exists():
        return []
    return sorted(p.name for p in base.iterdir() if p.is_dir())
