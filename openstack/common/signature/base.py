#!/usr/bin/python

#!/usr/bin/python

class Signature(object):

    @classmethod
    def load(cls, f):
        raise NotImplementedError

    def save(self, f):
        raise NotImplementedError


class Signer(object):

    def save_public_key(self, f):
        raise NotImplementedError

    def save(self, f):
        raise NotImplementedError

    def sign(self, message):
        raise NotImplementedError


class Verifier(object):

    def verify(self, signature, message):
        raise NotImplementedError


