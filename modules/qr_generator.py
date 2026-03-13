import qrcode
import io
import base64

def generate_qr_code(data, version=1, box_size=10, border=4):
    """
    Generate a QR code from the given data.
    
    Args:
        data: The data to encode in the QR code (URL or text)
        version: QR code version (1-40)
        box_size: Size of each box in the QR code
        border: Border size around the QR code
        
    Returns:
        Base64 encoded PNG image data URL
    """
    # Create QR code instance
    qr = qrcode.QRCode(
        version=version,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=box_size,
        border=border,
    )
    
    # Add data
    qr.add_data(data)
    qr.make(fit=True)
    
    # Create image
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Save to bytes
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    # Convert to base64
    img_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    # Return as data URL
    return f"data:image/png;base64,{img_base64}"

def generate_qr_with_logo(data, logo_path=None):
    """
    Generate a QR code with an optional logo in the center.
    
    Args:
        data: The data to encode
        logo_path: Path to logo image (optional)
        
    Returns:
        Base64 encoded PNG image data URL
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    img_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return f"data:image/png;base64,{img_base64}"
