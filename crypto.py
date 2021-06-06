import math
import random

# helper functions
class acol:
    HDR = '\033[95m'
    BLU = '\033[94m'
    CYN = '\033[96m'
    GRN = '\033[92m'
    YEL = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BLD = '\033[1m'
    UNDERLINE = '\033[4m'

def bign_print(x, name):
    spaces = " " * (18 - len(name))
    print(f"{name}:{spaces}{acol.YEL}" + str(x)[:18] + f"...{acol.END} ({len(str(x))} digits)")

def encrypt(m,e,n):
    return pow(m,e,n)

def decrypt(c,d,n):
    return pow(c,d,n)

def rabin_miller(n, s):
    # n is an odd number greater than 3
    # i.e. n - 1 = d * 2^r with d odd
    if n % 2 == 0:
        return True
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(s):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def gen_large_primes(min_bitlen):
    p = random.getrandbits(random.randint(min_bitlen, min_bitlen*2))
    q = random.getrandbits(random.randint(min_bitlen, min_bitlen*2))
    p = p + 1 if p % 2 == 0 else p
    q = q + 1 if q % 2 == 0 else q
    while not rabin_miller(p, 40):
        p = p + 2
    while not rabin_miller(q, 40):
        q = q + 2
    return (p, q)

def interactive_rsa():
    print(f"{acol.HDR}Welcome to RSA Interactive Mode.{acol.END}")
    input(f"Press ENTER to generate 2 large primes of size 1024 < len < 2048.  This can take some time.")
    (p, q) = gen_large_primes(min_bitlen=1024)
    bign_print(p, "p")
    bign_print(q, "q")
    n = p * q
    bign_print(n, "n = p * q")
    phin = phi(p,q)
    bign_print(phin, "φ(n)")

    e = 65537
    print(f"Using e = {acol.YEL}{e}{acol.END}.")
    input("Press ENTER to make sure e is coprime with φ(n).")
    res = math.gcd(e, phin)
    bign_print(res, "gcd(e,phi(n))")
    if res == 1:
        print("Good to go!")
    else:
        raise Exception("e and φ(n) are not coprime.  Please start over.")

    input(f"Press ENTER to find k s.t. e*d ≡ 1 (mod phi(n))")
    for k in range(1, e):
        d = (k * phin + 1) // e
        if (d * e) % phin == 1:
            print(f"Using k = {acol.BLU}{k}{acol.END}.")
            break
    else:
        raise Exception("Could not find k s.t. e*d ≡ 1 (mod phi(n)).  Please start over.")

    bign_print(d, "d")

    m = input("Enter secret message: ")
    encoded = m.encode("utf-8").hex()
    print(f"Hex encoded message: {acol.BLU}{encoded}{acol.END}")

    input("Press ENTER to encrypt your message.")
    c = encrypt(int(encoded, 16),e,n)
    bign_print(c, "encrypted msg c")

    input("Press ENTER to decrypt your message.")
    dec = hex(decrypt(c,d,n))
    bign_print(dec, "dec")
    dm = bytes.fromhex(dec[2:]).decode("utf-8")
    print(f"Decrypted message: {acol.GRN}{dm}{acol.END}")

def gen_keys():

    # public key
    (p, q) = gen_large_primes(min_bitlen=1024)
    n = p * q
    phin = (p - 1) * (q - 1)
    e = 65537
    if (math.gcd(e, phin) != 1):
        raise Exception("e and phi(n) are not coprime")
    with open("./publickey.pem", "w") as f:
        f.write("--- BEGIN PUBLIC KEY ---\n")
        f.write(str(e) + "." + str(n))
        f.write("\n--- END PUBLIC KEY ---\n")

    # private key
    for k in range(1, e):
        d = (k * phin + 1) // e
        if (d * e) % phin == 1:
            break
    else:
        raise Exception("Could not find k s.t. e*d ≡ 1 (mod phi(n))")
    with open("./privatekey.pem", "w") as f:
        f.write("--- BEGIN PRIVATE KEY ---\n")
        f.write(str(d))
        f.write("\n--- END PRIVATE KEY ---\n")

def encrypt_message(e,n):
    with open("./msg.txt", "r") as f:
        msg = f.read()
    msg_encoded = int(msg.encode("utf-8").hex(), 16)
    # c is the encrypted message
    c = pow(msg_encoded,e,n)
    with open("./msg.asc", "w") as f:
        f.write("--- BEGIN MESSAGE ---\n")
        f.write(str(c))
        f.write("\n--- END MESSAGE ---\n")

def decrypt_message(d,n):
    with open("./msg.asc", "r") as f:
        c = f.read().replace("--- BEGIN MESSAGE ---","") \
                    .replace("--- END MESSAGE ---","") \
                    .replace("\n", "")
    msg_encoded = hex(pow(int(c),d,n))
    msg = bytes.fromhex(msg_encoded[2:]).decode("utf-8")
    with open("./msg_decrypted.txt", "w") as f:
        f.write(msg)

def main():
    interactive_rsa()

if __name__ == "__main__":
    main()
