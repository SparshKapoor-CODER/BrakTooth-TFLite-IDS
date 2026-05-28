# Pipeline Notebooks

This folder contains the Jupyter notebooks that reproduce the full BrakTooth‑TFLite‑IDS workflow: feature extraction, preprocessing, model training, compression, and final evaluation.

## Notebook execution sequence
Run the notebooks in numeric order to reproduce the pipeline end‑to‑end:

1. `00_extract_features.ipynb` — Read raw PCAPs (benign and DoS), extract per‑packet features (`info`, `length`, `delta`) with the shared Scapy extractor, and export chronological train/val splits and intermediate CSVs.
2. `01_data_preprocessing.ipynb` — Load extracted packets, apply TF‑IDF vectorization to text fields, scale numeric features, encode labels, and save preprocessing artifacts (`tfidf_vectorizer`, `scaler`, `label_encoder`).
3. `02_model_training.ipynb` — Build and train the compact dense classifier (input → 32 → 16 → 2), use class weights and early stopping, and save the best Keras model.
4. `03_pruning_quantization.ipynb` — Apply pruning schedules to sparsify weights and export a post‑training INT8 quantized TFLite model (ids_model_int8.tflite, ≈5.95 KB).
5. `04_model_evaluation.ipynb` — Load the TFLite model and preprocessing artifacts, run evaluation on held‑out pcaps, and produce confusion matrices, confidence histograms, and final performance metrics.

## Important notes

- Chronological train/validation split: network packet frames are time‑dependent. Notebooks use an ordered split (early records → train, later records → val/test) to avoid temporal leakage and produce realistic validation metrics.

- Scapy extraction: feature extraction is implemented with `ble_extractor.py` and runs synchronously inside notebook cells. This avoids common event‑loop or subprocess locking problems and removes any dependency on `tshark`/Wireshark for the provided workflow.

- Artifacts: preprocessing and model artifacts are saved to `artifacts/` so later notebooks and `app.py` reuse them without recomputation.

## Quick start for notebooks
1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Place PCAP files in `data/raw/ble_pcaps/`.
3. Launch Jupyter (Lab or Notebook) from the repository root and run notebooks `00` → `04` in order.

## Reproducibility
- Random seeds and deterministic options used for training and preprocessing are documented within the notebooks. To reproduce results exactly, reuse the saved artifacts from `artifacts/` and run evaluation with the same TFLite artifact.
