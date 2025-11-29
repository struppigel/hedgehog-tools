from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import sys

# tested for log created by
# 9d59ab9bd34c3146c086feb0605048005433d4e9aba32516c07dbd02dd48b240 BrowserFixerSetup.exe 

def decrypt_aes(iv, data):
    keys = [b"BrowserFixerInstaller2024Key32!!", b"BuyBricksAIInstaller2024Key32!!!"]
    for key in keys:
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = cipher.decrypt(data)
            return unpad(plaintext, 16)
        except:
            pass
    print("Error: None of the keys worked!")
    return None

def read_entry(f):
    length_bytes = f.read(4)
    if not length_bytes: return None
    data_len = int.from_bytes(length_bytes, byteorder ="little")
    iv_bytes = f.read(16)
    data_len -= 16
    if not iv_bytes: return None
    data = f.read(data_len)
    if not data: return None
    return decrypt_aes(iv_bytes, data)
    
def decrypt_log(logfile):
    with open(logfile, "rb") as f:
        while True:
            decrypted_line = read_entry(f)
            if not decrypted_line: break
            decrypted_line = decrypted_line.decode('utf-8')
            print(decrypted_line)
    
def main():
    if len(sys.argv) != 2:
        print("Usage {sys.argv[0]} <input_file>")
        sys.exit(1)
    input_path = sys.argv[1]
    decrypt_log(input_path)

if __name__ == "__main__":
    main()
