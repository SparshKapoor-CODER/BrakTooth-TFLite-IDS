#!/usr/bin/env python3
"""
BLE DoS Detection – PCAP to CSV Inference Pipeline
==================================================
Uses the shared ble_extractor for consistent feature extraction.
"""

import os, sys, pickle, argparse, logging
import numpy as np
import pandas as pd
from ble_extractor import extract_packets_from_pcap

# TFLite runtime
try:
    from tflite_runtime.interpreter import Interpreter
except ImportError:
    import tensorflow as tf
    Interpreter = tf.lite.Interpreter

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def load_artifacts(artifacts_dir):
    global scaler, tfidf_vectorizer, label_encoder, interpreter, input_details, output_details
    with open(os.path.join(artifacts_dir, 'scaler.pkl'), 'rb') as f:
        scaler = pickle.load(f)
    with open(os.path.join(artifacts_dir, 'tfidf_vectorizer.pkl'), 'rb') as f:
        tfidf_vectorizer = pickle.load(f)
    with open(os.path.join(artifacts_dir, 'label_encoder.pkl'), 'rb') as f:
        label_encoder = pickle.load(f)
    model_path = os.path.join(artifacts_dir, 'models', 'ids_model_int8.tflite')
    interpreter = Interpreter(model_path=model_path)
    interpreter.allocate_tensors()
    input_details = interpreter.get_input_details()[0]
    output_details = interpreter.get_output_details()[0]
    logger.info(f"Loaded model from {model_path}")

def predict_packets(records):
    """
    Takes a list of extracted packets (each dict with 'info', 'length', 'delta') and
    returns DataFrame with predictions.
    """
    df = pd.DataFrame(records)
    if df.empty:
        return df
    # TF-IDF
    info_tfidf = tfidf_vectorizer.transform(df['info']).toarray()
    # Scale
    num = df[['length', 'delta']].values.astype(np.float32)
    num_scaled = scaler.transform(num)
    combined = np.hstack([info_tfidf, num_scaled]).astype(np.float32)
    # Quantize if needed
    if input_details['dtype'] == np.int8:
        scale, zp = input_details['quantization']
        combined = (combined / scale + zp).clip(-128, 127).astype(np.int8)
    interpreter.resize_tensor_input(input_details['index'], [combined.shape[0], combined.shape[1]])
    interpreter.allocate_tensors()
    interpreter.set_tensor(input_details['index'], combined)
    interpreter.invoke()
    output = interpreter.get_tensor(output_details['index'])
    if output_details['dtype'] == np.int8:
        scale, zp = output_details['quantization']
        output = (output.astype(np.float32) - zp) * scale
    # Softmax
    exp = np.exp(output - np.max(output, axis=1, keepdims=True))
    probs = exp / exp.sum(axis=1, keepdims=True)
    preds = label_encoder.inverse_transform(np.argmax(probs, axis=1))
    conf = np.max(probs, axis=1)
    df['prediction'] = preds
    df['confidence'] = conf
    for i, cls in enumerate(label_encoder.classes_):
        df[f'prob_{cls}'] = probs[:, i]
    return df

def main():
    parser = argparse.ArgumentParser(description='BLE DoS Detection – PCAP to CSV')
    parser.add_argument('--pcap', required=True)
    parser.add_argument('--output', default='predictions.csv')
    parser.add_argument('--artifacts', default='artifacts')
    parser.add_argument('--tshark', default=r'C:\Program Files\Wireshark\tshark.exe',
                        help='Path to tshark.exe')
    args = parser.parse_args()
    if not os.path.exists(args.pcap):
        logger.error(f"PCAP not found: {args.pcap}")
        sys.exit(1)
    load_artifacts(args.artifacts)
    records = extract_packets_from_pcap(args.pcap)
    logger.info(f"Extracted {len(records)} packets")
    if not records:
        logger.error("No packets extracted.")
        sys.exit(1)
    result_df = predict_packets(records)
    result_df.to_csv(args.output, index=False)
    logger.info(f"Saved predictions to {args.output}")
    # Summary
    cnt = result_df['prediction'].value_counts()
    logger.info("Predictions: " + ", ".join(f"{k}: {v}" for k,v in cnt.items()))
    logger.info(f"Avg confidence: {result_df['confidence'].mean():.4f}")

if __name__ == '__main__':
    main()