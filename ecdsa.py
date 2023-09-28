import random
# from hashlib import sha256
import py_ecc.secp256k1.secp256k1 as secp256k1
from py_ecc.typing import (PlainPoint2D)

class ECDSA:
  def __init__(self, order: int, generator_point: PlainPoint2D) -> (int, PlainPoint2D):
    self.order = order
    self.generator_point = generator_point

  def keygen(self):
    private_key = random.randint(0, self.order - 1)
    public_key = secp256k1.multiply(self.generator_point, private_key)
    # TODO: compress the public key
    
    return private_key, public_key
  
  def sign(self, message: int, private_key: int) -> PlainPoint2D:
    message_hash: int = ECDSA.hash_message(message)

    k: int = 94111259592240215275188773285036844871058226277992966241101117022315524122714
    # k = random.randint(1, self.order - 1)
    k_mod_inverse: int = pow(k, -1, self.order)

    random_point: PlainPoint2D = secp256k1.multiply(self.generator_point, k)
    random_point_x: int = random_point[0]
    signature_proof: int = k_mod_inverse * (message_hash + (private_key * random_point_x)) % self.order

    # if(signature_proof * 2 > self.order):
    #   signature_proof = self.order - signature_proof

    return random_point_x, signature_proof

  def verify(self, message: int, signature: PlainPoint2D, public_key: PlainPoint2D) -> bool:
    message_hash: int = ECDSA.hash_message(message)
    
    sig_proof_mod_inverse: int = pow(signature[1], -1, self.order)

    random_point: PlainPoint2D = secp256k1.add(
      secp256k1.multiply(
        self.generator_point,
        (message_hash * sig_proof_mod_inverse)
      ),
      secp256k1.multiply(
        public_key,
        (signature[0] * sig_proof_mod_inverse)
      )
    )
    random_point_x: int = random_point[0]

    return random_point_x == signature[0]
  
  def hash_message(message: int) -> int:
    return hash(message)

# Test
my_message: int = hash(1337)

ecdsa = ECDSA(115792089237316195423570985008687907852837564279074904382605163141518161494337, (55066263022277343669578718895168534326250603453777594175500187360389116729240,32670510020758816978083085130507043184471273380659243275938904335757337482424))
print("Your keys:")
keys = ecdsa.keygen()
print(keys)
print("\nSigning message...")
signature = ecdsa.sign(my_message, 123456789)
print("\nSignature:")
print(signature)
print("\nPY_ECC signature:")
print(secp256k1.ecdsa_raw_sign(my_message.to_bytes(32, 'big'), keys[0].to_bytes(32, 'big')))
# print("Verifying signature...")
# verification = ecdsa.verify(1337, signature, keys[1])
# print("Verification:")
# print(verification)
