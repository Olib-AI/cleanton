//! Pure-Rust ONNX inference with `tract`.
//!
//! The trained classifier (`models/file_classifier_v2.onnx`) and its sidecar
//! (`models/file_classifier_v2.json`) are embedded into the binary at compile
//! time, so the shipped app needs no external model file and no native
//! `onnxruntime` library. The model and the parsed sidecar are built once,
//! lazily, and cached for the process lifetime.
//!
//! The network operates on *standardized* features; we apply the exact same
//! mean/std constants the Python trainer recorded in the sidecar, so Rust and
//! Python produce identical outputs for identical raw feature vectors. The 3
//! categorical slots (extension/parent/grandparent ids) carry identity
//! constants (mean 0, std 1) — the graph consumes the raw ids via in-graph
//! embeddings, and the exported model emits raw logits (softmax runs here).

use std::sync::OnceLock;

use serde::Deserialize;
use tract_onnx::prelude::*;

use crate::{
    CleanupLabel, EMBEDDED_MODEL_BYTES, EMBEDDED_SIDECAR, FEATURE_COUNT, MlClassification, MlError,
    MlResult, MlUnavailableReason,
};

type RunnableOnnx = RunnableModel<TypedFact, Box<dyn TypedOp>, TypedModel>;

#[derive(Debug, Deserialize)]
struct Normalization {
    mean: Vec<f32>,
    std: Vec<f32>,
}

#[derive(Debug, Deserialize)]
struct Sidecar {
    feature_count: usize,
    label_order: Vec<String>,
    normalization: Normalization,
}

struct Prepared {
    model: RunnableOnnx,
    mean: [f32; FEATURE_COUNT],
    std: [f32; FEATURE_COUNT],
    labels: [CleanupLabel; 4],
}

fn build() -> Result<Prepared, String> {
    let sidecar: Sidecar =
        serde_json::from_str(EMBEDDED_SIDECAR).map_err(|err| format!("sidecar parse: {err}"))?;

    if sidecar.feature_count != FEATURE_COUNT
        || sidecar.normalization.mean.len() != FEATURE_COUNT
        || sidecar.normalization.std.len() != FEATURE_COUNT
    {
        return Err(format!(
            "sidecar feature count mismatch: expected {FEATURE_COUNT}, got {}",
            sidecar.feature_count
        ));
    }

    let mut mean = [0.0_f32; FEATURE_COUNT];
    let mut std = [1.0_f32; FEATURE_COUNT];
    mean.copy_from_slice(&sidecar.normalization.mean);
    std.copy_from_slice(&sidecar.normalization.std);

    let labels = label_order(&sidecar.label_order)?;

    let model = tract_onnx::onnx()
        .model_for_read(&mut std::io::Cursor::new(EMBEDDED_MODEL_BYTES))
        .map_err(|err| format!("onnx load: {err}"))?
        .with_input_fact(0, f32::fact([1, FEATURE_COUNT]).into())
        .map_err(|err| format!("onnx input fact: {err}"))?
        .into_optimized()
        .map_err(|err| format!("onnx optimize: {err}"))?
        .into_runnable()
        .map_err(|err| format!("onnx runnable: {err}"))?;

    Ok(Prepared {
        model,
        mean,
        std,
        labels,
    })
}

fn label_order(order: &[String]) -> Result<[CleanupLabel; 4], String> {
    if order.len() != 4 {
        return Err(format!("expected 4 labels, got {}", order.len()));
    }
    let mut labels = [CleanupLabel::Keep; 4];
    for (slot, name) in labels.iter_mut().zip(order) {
        *slot = match name.as_str() {
            "keep" => CleanupLabel::Keep,
            "safe-to-remove" => CleanupLabel::SafeToRemove,
            "likely-junk" => CleanupLabel::LikelyJunk,
            "uncertain" => CleanupLabel::Uncertain,
            other => return Err(format!("unknown label in sidecar: {other}")),
        };
    }
    Ok(labels)
}

fn prepared() -> Result<&'static Prepared, &'static str> {
    static PREPARED: OnceLock<Result<Prepared, String>> = OnceLock::new();
    PREPARED.get_or_init(build).as_ref().map_err(String::as_str)
}

fn unavailable() -> MlError {
    MlError::InferenceUnavailable {
        reason: MlUnavailableReason::NoInferenceBackend,
        model_path: None,
    }
}

/// Run the embedded classifier on a raw 53-feature vector and return the raw
/// logits (one per label, in the sidecar's label order). Exposed so golden
/// parity tests can assert logit-level agreement with the Python exporter.
pub fn logits_for_features(values: &[f32; FEATURE_COUNT]) -> MlResult<[f32; 4]> {
    let prepared = prepared().map_err(|_| unavailable())?;

    let mut normalized = [0.0_f32; FEATURE_COUNT];
    for ((slot, &value), (&mean, &std)) in normalized
        .iter_mut()
        .zip(values.iter())
        .zip(prepared.mean.iter().zip(prepared.std.iter()))
    {
        *slot = (value - mean) / std;
    }

    let input: Tensor =
        tract_ndarray::Array2::from_shape_vec((1, FEATURE_COUNT), normalized.to_vec())
            .map_err(|_| unavailable())?
            .into();

    let outputs = prepared
        .model
        .run(tvec!(input.into()))
        .map_err(|_| unavailable())?;

    let view = outputs
        .first()
        .ok_or_else(unavailable)?
        .to_array_view::<f32>()
        .map_err(|_| unavailable())?;
    let mut logits = [0.0_f32; 4];
    let mut produced = 0_usize;
    for (slot, &value) in logits.iter_mut().zip(view.iter()) {
        *slot = value;
        produced = produced.saturating_add(1);
    }
    if produced != 4 || view.len() != 4 {
        return Err(unavailable());
    }
    Ok(logits)
}

/// Run the embedded classifier on a raw 53-feature vector and return the
/// calibrated prediction (argmax label + softmax probability of that label).
pub fn classify_features(values: &[f32; FEATURE_COUNT]) -> MlResult<MlClassification> {
    let prepared = prepared().map_err(|_| unavailable())?;
    let logits = logits_for_features(values)?;

    let probs = softmax(&logits);
    let (index, confidence) = argmax(&probs);

    // `index` is the argmax over `probs` (`[f32; 4]`) and `labels` has exactly 4
    // entries, so `index` is always in bounds; `.get` keeps it panic-free.
    Ok(MlClassification {
        label: *prepared.labels.get(index).ok_or_else(unavailable)?,
        confidence,
    })
}

fn softmax(logits: &[f32]) -> [f32; 4] {
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let mut exps = [0.0_f32; 4];
    let mut sum = 0.0_f32;
    for (slot, &logit) in exps.iter_mut().zip(logits) {
        let value = (logit - max).exp();
        *slot = value;
        sum += value;
    }
    for slot in &mut exps {
        *slot /= sum;
    }
    exps
}

fn argmax(probs: &[f32; 4]) -> (usize, f32) {
    // Equivalent to scanning from index 0 keeping the first strict maximum:
    // strictly-greater values replace, ties keep the earlier index.
    probs
        .iter()
        .copied()
        .enumerate()
        .fold((0, f32::NEG_INFINITY), |(best_i, best_v), (i, v)| {
            if v > best_v { (i, v) } else { (best_i, best_v) }
        })
}
