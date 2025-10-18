from crypto import encrypt_scytale, decrypt_scytale, encrypt_caesar, decrypt_caesar, encrypt_vigenere, decrypt_vigenere, encrypt_railfence, decrypt_railfence

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

def test_scytale():
    f = open("tests/scytale-tests.txt", "r")
    for line in f.readlines():
        parts = line.split("\t")

        plaintext = parts[0].strip()
        rails=int(parts[1].strip())
        ciphertext = parts[2].strip()

        encrypted = encrypt_scytale(plaintext,rails)
        decrypted = decrypt_scytale(ciphertext,rails)

        assert encrypted == ciphertext, f"Scytale encryption failed: {plaintext} expected {ciphertext}"
        assert decrypted == plaintext, f"Scytale decryption failed: {ciphertext} expected {plaintext}"

    print("Scytale test passed")


def test_railfence():
    f = open("tests/railfence-tests.txt", "r")
    for line in f.readlines():
        parts = line.split("\t")

        plaintext = parts[0].strip()
        rails=int(parts[1].strip())
        ciphertext = parts[2].strip()

        encrypted = encrypt_railfence(plaintext,rails)
        decrypted = decrypt_railfence(ciphertext,rails)

        assert encrypted == ciphertext, f"Railfence encryption failed: {plaintext} expected {ciphertext}"
        assert decrypted == plaintext, f"Railfence decryption failed: {ciphertext} expected {plaintext}"

    print("Railfence test passed")

if __name__ == "__main__":
    test_caesar()
    test_vigenere()
    test_railfence()
    test_scytale()
