import hashlib

def sha256_encrypt(text):
    return hashlib.sha256(text.encode()).hexdigest()

# Example usage
input_text = "admin123"
estimated_output="240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9"
encrypted = sha256_encrypt(input_text)
if encrypted == estimated_output:
    print("True")
print(f"SHA256 hash of '{input_text}': {encrypted}")