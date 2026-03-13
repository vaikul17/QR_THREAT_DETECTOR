import cv2
import numpy as np
import base64

# Initialize the OpenCV QR Code detector
detector = cv2.QRCodeDetector()

def decode_qr(path):
    """Decode QR code from image file path."""
    img = cv2.imread(path)
    if img is None:
        return None
    data, bbox, _ = detector.detectAndDecode(img)
    return data if data else None

def decode_qr_from_base64(image_data):
    """Decode QR code from base64 encoded image data."""
    try:
        if ',' in image_data:
            image_data = image_data.split(',')[1]
        img_bytes = base64.b64decode(image_data)
        nparr = np.frombuffer(img_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return None
        data, bbox, _ = detector.detectAndDecode(img)
        return data if data else None
    except Exception as e:
        print(f"Error decoding QR from base64: {e}")
        return None

def decode_qr_from_bytes(image_bytes):
    """Decode QR code from image bytes."""
    try:
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return None
        data, bbox, _ = detector.detectAndDecode(img)
        return data if data else None
    except Exception as e:
        print(f"Error decoding QR from bytes: {e}")
        return None

def bulk_decode_qr(image_paths):
    """Decode multiple QR codes from a list of image paths."""
    results = []
    for path in image_paths:
        try:
            decoded = decode_qr(path)
            results.append((path, decoded))
        except Exception as e:
            print(f"Error processing {path}: {e}")
            results.append((path, None))
    return results
