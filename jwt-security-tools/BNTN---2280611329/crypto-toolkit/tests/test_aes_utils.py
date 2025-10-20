import tempfile, os
from securitycrypto import aes_utils

def test_encrypt_decrypt():
    original_content = "Hello World!".encode('utf-8')
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = tmp.name

    try:
        encoded_key = aes_utils.encrypt_file_aes(tmp_path, 'unused_password')
        encryted_path = tmp_path + ".enc"
        assert os.path.exists(encryted_path), "File mã hoán không tồn tại"
        decrypted_path = aes_utils.decrypt_file_aes(encryted_path, encoded_key)
        assert os.path.exists(decrypted_path),"file giải mã không tồn tại"
        with open(decrypted_path, "rb") as f:
         decrypted_content = f.read()
        assert decrypted_content == original_content , "nội dung không khớp"
    finally:
        for path in (tmp_path, tmp_path + ".enc", tmp_path + ".dec"):
          if os.path.exists(path):  
            os.remove(path)