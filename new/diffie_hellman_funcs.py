import random
import math
import hashlib
import base64
from pyDes import *
from Crypto.Util import number

# 用辗转相除求最大公因子
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# 判断是否为素数
def judgeprime(a):
    if a < 2:
        return False
    for i in range(2, int(math.sqrt(a)) + 1):
        if a % i == 0:
            return False
    return True

# 生成伪素数
def pseudoprime(prime):
    while True:
        pseudo = random.randint(5000000, 50000000) * 2 + 1
        for i in prime:
            if pseudo % i == 0:
                break
        else:
            return pseudo

# 判断一定范围内的素数，生成素数列表
def primelist():
    prime = [2]
    for i in range(3, 10008):
        if i % 2 == 1 and judgeprime(i):
            prime.append(i)
    return prime

# 求素数p的原根
def primitive_root(p):
    def prime_factors(n):
        factors = []
        d = 2
        while d * d <= n:
            if n % d == 0:
                factors.append(d)
                n //= d
            else:
                d += 1
        if n > 1:
            factors.append(n)
        return factors

    phi = p - 1
    factors = prime_factors(phi)
    for g in range(2, p):
        if all(pow(g, phi // factor, p) != 1 for factor in factors):
            return g
    return None

# 产生一个随机素数p
def gen_p():
    bigprime = pseudoprime(primelist())
    return bigprime

# 产生p的一个随机的原根
def gen_a(p):
    ret = primitive_root(p)
    return ret

# DES加密
def des_encrypt(message, key):
    if len(key) > 8:
        key = key[:8]
    if len(key) < 8:
        key = key.zfill(8)
    Key = bytes(key, "utf-8")
    Des_IV = b"\x22\x33\x35\x81\xBC\x38\x5A\xE7"
    ke = des(Key, CBC, Des_IV, pad=None, padmode=PAD_PKCS5)
    EncryptM = ke.encrypt(message)
    return base64.b64encode(EncryptM).decode('utf-8')

# DES解密
def des_decrypt(message, key):
    if len(key) > 8:
        key = key[:8]
    if len(key) < 8:
        key = key.zfill(8)
    Key = bytes(key, "utf-8")
    Des_IV = b"\x22\x33\x35\x81\xBC\x38\x5A\xE7"
    ke = des(Key, CBC, Des_IV, pad=None, padmode=PAD_PKCS5)
    DecryptM = ke.decrypt(base64.b64decode(message))
    return DecryptM.decode('utf-8')

# 模重复平方算法，x为底数，y为指数，p为模
def quick_pow_mod(x, y, p):
    x = x % p
    ret = 1
    while y != 0:
        if y % 2 == 1:
            ret = ret * x % p
        x = x * x % p
        y //= 2
    return ret

# RSA密钥生成
def generate_rsa_keys(key_size=2048):
    e = 65537  # 常用的公钥指数
    while True:
        p = number.getPrime(key_size // 2)
        q = number.getPrime(key_size // 2)
        n = p * q
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) == 1:
            break
    d = number.inverse(e, phi)
    return (e, d, n)

# RSA签名
def rsa_sign(private_key, message):
    e, d, n = private_key
    hash_value = int.from_bytes(hashlib.sha256(message).digest(), byteorder='big')
    signature = pow(hash_value, d, n)
    return signature

# RSA验证签名
def rsa_verify(public_key, message, signature):
    e, n = public_key
    hash_value = int.from_bytes(hashlib.sha256(message).digest(), byteorder='big')
    hash_from_signature = pow(signature, e, n)
    return hash_value == hash_from_signature

# Diffie-Hellman 密钥交换
def diffie_hellman(p, g, a, b):
    # Alice 公钥 A
    A = quick_pow_mod(g, a, p)
    # Bob 公钥 B
    B = quick_pow_mod(g, b, p)

    # Alice 生成RSA密钥对
    alice_private_key = generate_rsa_keys()
    alice_public_key = (alice_private_key[0], alice_private_key[2])

    # Bob 生成RSA密钥对
    bob_private_key = generate_rsa_keys()
    bob_public_key = (bob_private_key[0], bob_private_key[2])

    # Alice 用她的RSA私钥对她的DH公钥签名
    alice_signature = rsa_sign(alice_private_key, str(A).encode())

    # Bob 用他的RSA私钥对他的DH公钥签名
    bob_signature = rsa_sign(bob_private_key, str(B).encode())

    # 验证签名
    if not rsa_verify(alice_public_key, str(A).encode(), alice_signature):
        raise Exception("Alice's DH public key signature verification failed")
    if not rsa_verify(bob_public_key, str(B).encode(), bob_signature):
        raise Exception("Bob's DH public key signature verification failed")

    # 计算共享密钥
    shared_key_alice = quick_pow_mod(B, a, p)
    shared_key_bob = quick_pow_mod(A, b, p)

    # 确认共享密钥相同
    assert shared_key_alice == shared_key_bob, "Shared keys do not match!"
    shared_key = str(shared_key_alice)

    alice_info = {
        'dh_public_key': A,
        'rsa_public_key': alice_public_key,
        'signature': alice_signature,
        'shared_key': shared_key[:8]
    }

    bob_info = {
        'dh_public_key': B,
        'rsa_public_key': bob_public_key,
        'signature': bob_signature,
        'shared_key': shared_key[:8]
    }

    return shared_key[:8], alice_info, bob_info
