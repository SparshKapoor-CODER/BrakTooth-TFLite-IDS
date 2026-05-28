## BrakTooth‑TFLite‑IDS — BLE DoS Detector

A lightweight Bluetooth Low Energy (BLE) Denial‑of‑Service (DoS) intrusion detection system. The final TFLite INT8 model is ~5.95 KB, runs in microseconds per packet, and achieves >98% accuracy on held‑out, unseen test captures.

## Overview
BrakTooth‑TFLite‑IDS converts raw BLE pcap captures into per‑packet feature vectors (Scapy extraction → TF‑IDF tokenization → scaling) and classifies packets using a compact neural network. The full workflow — extraction, preprocessing, training, pruning, quantization, and evaluation — is reproducible via the included Jupyter notebooks. Use `app.py` for pcap→CSV inference using saved preprocessing artifacts and the TFLite model.

## Features
- End‑to‑end pipeline: pcap → Scapy feature extraction → TF‑IDF + scaling → model training → pruning → INT8 quantization → TFLite inference.
- Chronological train/validation split to prevent time‑based leakage and ensure realistic evaluation.
- Extremely small footprint: TFLite INT8 model ≈ 5.95 KB, suitable for edge/microcontroller deployment.
- Very low latency: ~5 µs inference per packet (CPU measurement).
- Reproducible notebooks and saved preprocessing artifacts for deterministic inference.

## Dataset (CICIoMT2024 Bluetooth)
The model is trained on the CICIoMT2024 Bluetooth DoS dataset (benign + DoS pcaps). Download from Kaggle:

https://www.kaggle.com/datasets/cyberdeeplearning/ciciomt2024

Files to place under `data/raw/ble_pcaps/`:
- Bluetooth_Benign_train.pcap
- Bluetooth_DoS_train.pcap
- Bluetooth_Benign_test.pcap
- Bluetooth_DoS_test.pcap

Put the train pcaps for preprocessing/training and the test pcaps in the same folder for evaluation as shown above.

## Quick start
1. Create and activate a Python 3.10+ environment and install dependencies:

```bash
python -m venv venv
# On macOS / Linux
source venv/bin/activate
# On Windows
venv\Scripts\activate
pip install -r requirements.txt
```

2. Place the required pcap files in `data/raw/ble_pcaps/` (see Dataset section).

3. Run the Jupyter notebooks in numeric order (recommended):

- `notebooks/00_extract_features.ipynb`
- `notebooks/01_data_preprocessing.ipynb`
- `notebooks/02_model_training.ipynb`
- `notebooks/03_pruning_quantization.ipynb`
- `notebooks/04_model_evaluation.ipynb`

4. Run inference on a pcap with `app.py`:

```bash
python app.py --input data/raw/ble_pcaps/Bluetooth_Benign_test.pcap --output test_benign.csv
python app.py --input data/raw/ble_pcaps/Bluetooth_DoS_test.pcap --output test_dos.csv
```

`app.py` will load the saved `tfidf_vectorizer`, `scaler`, and the TFLite INT8 model from `artifacts/`.

## Model architecture & compression
- Input: 52 features per packet (TF‑IDF tokens + numeric features such as packet length and inter‑packet delta time).
- Network: Dense(52 → 32) → Dense(32 → 16) → Dense(16 → 2)
	- Hidden activations: ReLU; output: Softmax (2 classes: benign / DoS).
	- Training: class weights, early stopping, chronological validation split (notebooks document hyperparameters).
- Compression: pruning (magnitude/structured as in notebook) followed by post‑training INT8 quantization.
- Final artifact: `artifacts/models/ids_model_int8.tflite` (~5.95 KB).

## Performance (held‑out pcaps)
| Test file | Packets | Accuracy | Avg. confidence |
|---|---:|---:|---:|
| Bluetooth_Benign_test.pcap | 65,330 | 98.17% | 0.727 |
| Bluetooth_DoS_test.pcap | 251,708 | 99.84% | 0.730 |

- Inference time (per packet): ~5 µs (CPU measurement)

Notes:
- Reported metrics are evaluated on unseen pcap captures (not mixed fragments) to reflect realistic deployment conditions.
- Average confidence is the mean softmax score associated with the predicted class.

## Project structure
```
BrakTooth-TFLite-IDS/
├── app.py                          # pcap -> csv inference runner
├── ble_extractor.py                # Scapy-based feature extractor used by notebooks and app.py
├── README.md                       # Project README (this file)
├── requirements.txt                # Python dependencies
├── .gitignore
├── artifacts/
│   ├── scaler/                     # saved scaler objects (e.g., StandardScaler)
│   ├── tfidf_vectorizer/           # saved TF‑IDF vectorizer
│   ├── label_encoder/              # saved label encoder
│   └── models/
│      ├── best_model.keras
│      ├── ids_pruned.h5
│      └── ids_model_int8.tflite
├── data/
│   ├── raw/
│   │  └── ble_pcaps/               # downloaded PCAPs (train & test)
│   └── processed/                  # saved .npz / .npy arrays (X_train, y_train, ...)
└── notebooks/
	 ├── 00_extract_features.ipynb
	 ├── 01_data_preprocessing.ipynb
	 ├── 02_model_training.ipynb
	 ├── 03_pruning_quantization.ipynb
	 └── 04_model_evaluation.ipynb
```

## Requirements
- Python 3.10 or later recommended.
- Key packages (see `requirements.txt`): `scapy`, `pandas`, `numpy`, `scipy`, `scikit-learn`, `tensorflow`, `matplotlib`, `seaborn`, `tensorflow-model-optimization`, `jupyter`.
- `scapy` is used for pcap parsing; `tshark` is not required for the provided Scapy‑based extractor.

## Reproducibility and best practices
- Notebooks use a chronological (time‑ordered) train/validation split to avoid leakage between temporally adjacent packets or captures.
- Save and reuse preprocessing artifacts (`tfidf_vectorizer`, `scaler`, `label_encoder`) from `artifacts/` to ensure identical preprocessing at inference time.
- Seeds and deterministic steps are documented in the notebooks where applicable.

## License & use
Provided for educational and research purposes. Use the CICIoMT2024 dataset according to its license and citation requirements. If you reuse this work in publications or products, please credit the repository and dataset.


