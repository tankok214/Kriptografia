from crypto import encrypt_caesar, decrypt_caesar, encrypt_vigenere, decrypt_vigenere

def test_caesar():
    f = open("tests/caesar-tests.txt", "r")
    for line in f.readlines():
        parts = line.split("\t")

        plaintext = parts[0].strip()
        ciphertext = parts[1].strip()

        encrypted = encrypt_caesar(plaintext)
        decrypted = decrypt_caesar(ciphertext)

        assert encrypted == ciphertext, f"Caesar encryption failed: {plaintext} -> {encrypted}, expected {ciphertext}"
        assert decrypted == plaintext, f"Caesar decryption failed: {ciphertext} -> {decrypted}, expected {plaintext}"

    print("Caesar test passed")

def test_vigenere():
    f = open("tests/vigenere-tests.txt", "r")
    for line in f.readlines():
        parts = line.split("\t")

        plaintext = parts[0].strip()
        keyword = parts[1].strip()
        ciphertext = parts[2].strip()

        encrypted = encrypt_vigenere(plaintext, keyword)
        decrypted = decrypt_vigenere(ciphertext, keyword)

        assert encrypted == ciphertext, f"Vigenere encryption failed: {plaintext} with {keyword} -> {encrypted}, expected {ciphertext}"
        assert decrypted == plaintext, f"Vigenere decryption failed: {ciphertext} with {keyword} -> {decrypted}, expected {plaintext}"

    print("Vigenere test passed")

if __name__ == "__main__":
    test_caesar()
    test_vigenere()
