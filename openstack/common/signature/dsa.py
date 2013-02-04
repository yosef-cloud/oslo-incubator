#!/usr/bin/python

from Crypto.PublicKey import DSA
from Crypto.Hash import SHA
from Crypto.Random import random
from base import *

class DSASignature(Signature):

    def __init__(self, rs):
        self.rs = rs

#    @classmethod
#    def load(cls, f):
#        r = int(f.readline())
#        s = int(f.readline())
#        return DSASignature((r, s))
#
#    def save(self, f):
#        print>>f, self.rs[0]
#        print>>f, self.rs[1]


class DSASigner(Signer):

    def __init__(self, key_file=None):
        if key_file == None:
            self.key = DSA.generate(1024)
            return
        try:
            y = int(key_file.readline())
            g = int(key_file.readline())
            p = int(key_file.readline())
            q = int(key_file.readline())
            x = int(key_file.readline())
        except ValueError:
            raise ValueError('Unable to reconstruct DSA private key')
        self.key = DSA.construct((y, g, p, q, x))


    def save(self, f):
        print>>f, self.key.y
        print>>f, self.key.g
        print>>f, self.key.p
        print>>f, self.key.q
        print>>f, self.key.x

    def save_public_key(self, f):
        print>>f, self.key.y
        print>>f, self.key.g
        print>>f, self.key.p
        print>>f, self.key.q

    def sign(self, message):
        h = SHA.new(message).digest()
        k = random.StrongRandom().randint(1, self.key.q - 1)
        return DSASignature(self.key.sign(h, k))


class DSAVerifier(Verifier):

    def __init__(self, public_key_file):
        try:
            y = int(public_key_file.readline())
            g = int(public_key_file.readline())
            p = int(public_key_file.readline())
            q = int(public_key_file.readline())
        except ValueError:
            raise ValueError('Unable to reconstruct DSA public key')
        self.key = DSA.construct((y, g, p, q))

    def verify(self, signature, message):
        h = SHA.new(message).digest()
        return self.key.verify(h, signature.rs)


if __name__ == '__main__':
    f = open('/tmp/public_key_integers','w+')
    s = DSASigner()
    s.save_public_key(f)
    signature = s.sign("hello")
    f.seek(0)
    v = DSAVerifier(f)
    print v.verify(signature, "hello")
    
