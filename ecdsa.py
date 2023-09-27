import random
import hashlib
import py_ecc.secp256k1 as secp256k1

class ECDSA:
  def __init__(self, order, generator_point):
    self.order = order
    self.generator_point = generator_point

  def keygen(self):
    private_key = random.randint(0, self.order - 1)
    public_key = tuple([x * private_key for x in self.generator_point])
    # TODO: compress the public key
    
    return private_key, public_key
    
  def sign(self, message, private_key):
    message_hash = hashlib.new('sha256', bytes(message,'utf-8')).hexdigest()

    k = random.randint(1, self.order - 1)
    random_point = tuple([x * k for x in self.generator_point])
    random_point_x = random_point[0]
    signature_proof = (k^-1 * (message_hash + (private_key * random_point_x))) % self.order

    return random_point, signature_proof

  def verify(self, message, signature, public_key):
    message_hash = hashlib.new('sha256', bytes(message,'utf-8')).hexdigest()
    sig_proof_mod_inverse = signature[1]^-1 % self.order
    random_point_x = (message_hash * sig_proof_mod_inverse) * self.generator_point + (signature[1] * sig_proof_mod_inverse) * public_key[0]

    return random_point_x == signature[1]

# Test
ecdsa = ECDSA(115792089237316195423570985008687907852837564279074904382605163141518161494337, (55066263022277343669578718895168534326250603453777594175500187360389116729240,32670510020758816978083085130507043184471273380659243275938904335757337482424))
print("Your keys:")
keys = ecdsa.keygen()
print(keys)
print("Signing message...")
signature = ecdsa.sign("Hello world!", 123456789)
print("Signature:")
print(signature)
print("Verifying signature...")
verification = ecdsa.verify("Hello world!", signature, keys[1])
print("Verification:")
print(verification)
