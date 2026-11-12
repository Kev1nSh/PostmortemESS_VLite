import io 
import outlookmsgfile

def convert_msg_to_eml(msg_bytes: bytes) -> bytes:
    """
    Convert a .msg file (Outlook email format) to .eml format (standard email format).
    This function uses the 'convert-outlook-msg-file' library to perform the conversion.
    """
    if not isinstance(msg_bytes, bytes) or not msg_bytes:
        raise ValueError("Input must be non-empty bytes")

    message = outlookmsgfile.load(io.BytesIO(msg_bytes))

    eml_bytes = message.as_bytes()

    if not eml_bytes:
        raise ValueError("MSG conversion failed, resulting .eml is empty")
    
    return eml_bytes
