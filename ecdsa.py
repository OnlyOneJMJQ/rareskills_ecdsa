import random
from hashlib import sha256
import py_ecc.secp256k1.secp256k1 as secp256k1
from py_ecc.typing import (PlainPoint2D)
from rich import print

class ECDSA:
  def __init__(self, order: int, generator_point: PlainPoint2D) -> (int, PlainPoint2D):
    self.order = order
    self.generator_point = generator_point

  def keygen(self):
    private_key = random.randint(0, self.order - 1)
    public_key = secp256k1.multiply(self.generator_point, private_key)
    # TODO: compress the public key?
    
    return private_key, public_key
  
  def sign(self, message: bytes, private_key: int) -> PlainPoint2D:
    message_int: int = secp256k1.bytes_to_int(message)

    # k: int = 94111259592240215275188773285036844871058226277992966241101117022315524122714
    k = random.randint(1, self.order - 1)
    k_mod_inverse: int = pow(k, -1, self.order)

    random_point: PlainPoint2D = secp256k1.multiply(self.generator_point, k)
    random_point_x: int = random_point[0]
    signature_proof: int = k_mod_inverse * (message_int + private_key * random_point_x) % self.order

    return random_point_x, signature_proof

  def verify(self, message: bytes, signature: PlainPoint2D, public_key: PlainPoint2D) -> bool:
    message_int: int = secp256k1.bytes_to_int(message)
    
    sig_proof_mod_inverse: int = pow(signature[1], -1, self.order)

    random_point: PlainPoint2D = secp256k1.add(
      secp256k1.multiply(
        self.generator_point,
        (message_int * sig_proof_mod_inverse)
      ),
      secp256k1.multiply(
        public_key,
        (signature[0] * sig_proof_mod_inverse)
      )
    )
    random_point_x: int = random_point[0]

    return random_point_x == signature[0]

def hash_message(message: str | int):
  if isinstance(message, str):
    return sha256(message.encode('utf-8')).hexdigest()
  elif isinstance(message, int):
    return sha256(message.to_bytes(32, 'big')).hexdigest()
  else:
    raise TypeError("Message must be of type str or int")

# Test
message: str = "Hello World!"
message_hash: bytes = hash_message(message)

print("\nECDSA TEST\n==========\n")

print("[yellow]Initializing...[/yellow]\n")
ecdsa: ECDSA = ECDSA(115792089237316195423570985008687907852837564279074904382605163141518161494337, (55066263022277343669578718895168534326250603453777594175500187360389116729240,32670510020758816978083085130507043184471273380659243275938904335757337482424))

print("[yellow]Generating keys...[/yellow]\n")
keys = ecdsa.keygen()
print("Keys\n----")
print("Public Key: (" + str(keys[1][0]) + ",")
print("             " + str(keys[1][1]) + ")")
print("Private Key: " + str(keys[0]) + "\n")

print("[yellow]Signing message...[/yellow]\n")
signature = ecdsa.sign(message_hash, keys[0])
print("Signature\n---------")
print("Random Point X (r): " + str(signature[0]))
print("Signature Proof (s): " + str(signature[1]) + "\n")

# print("PY_ECC Signature\n----------------")
# pyecc_sig = secp256k1.ecdsa_raw_sign(message_hash, keys[0].to_bytes(32, 'big'))
# print("Random Point X (r): " + str(pyecc_sig[1]))
# print("Signature Proof (s): " + str(pyecc_sig[2]) + "\n")

print("[yellow]Verifying signature...[/yellow]\n")
verification = ecdsa.verify(message_hash, signature, keys[1])
print("Verified: " + str(verification))
