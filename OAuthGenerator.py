# I got this from a stack overflow post, don't remember which one
# TODO: Find which post I got this from and credit it


class OAuthGenerator:
    def __init__(self):
        return

    def code_from_hash(self, hash, code_length=6):
        if ((1 > code_length) or
                (10 < code_length)):
            raise ValueError('code_length must be in the range [1,10]')
        if not isinstance(hash, bytes):
            raise TypeError('hash must be a byte string')
        if 4 != len(hash):
            raise ValueError(
                'hmac must be a byte string of length 8 (4 bytes)')

        int_hash = int.from_bytes(hash, 'big', signed=False)
        code = int_hash % (10 ** code_length)
        code_string = str(code)
        # pad on left as needed to achieve codeLength digits
        code_string = "0" * (code_length - len(code_string)) + code_string
        return code_string

    def counter_from_time(self, period=30):
        import time
        import datetime

        # make sure period is an integer
        period = int(period)
        if 0 >= period:
            raise ValueError('period must be positive integer')

        local_now = datetime.datetime.now()
        seconds_now = time.mktime(local_now.timetuple())
        intervals = seconds_now // period
        remaining_seconds = seconds_now - (intervals * period)
        counter = self.num_to_counter(intervals)
        return counter, remaining_seconds

    def convert_base32_secret_key(self, base32_secret_key):
        import base64
        import binascii

        secret_length = len(base32_secret_key)
        pad_length = (8 - (secret_length % 8)) % 8
        pad = "=" * pad_length
        base32_secret_key = base32_secret_key + pad

        try:
            secret_key = base64.b32decode(base32_secret_key)
        except binascii.Error:
            raise ValueError(
                'Wrong length, incorrect padding, or embedded whitespace')
        return secret_key

    def generate_code_from_time(self, secret_key, code_length=6, period=30):
        period = int(period)
        if 0 >= period:
            raise ValueError('period must be positive integer')
        # make sure codeLength is an integer
        code_length = int(code_length)
        if ((1 > code_length) or
                (10 < code_length)):
            raise ValueError('code_length must be in the range [1,10]')
        if not isinstance(secret_key, bytes):
            secret_key = self.convert_base32_secret_key(secret_key)

        message, remaining_seconds = self.counter_from_time(period=period)
        hmac = self.generate_hmac(secret_key, message)
        truncated_hash = self.hash_from_hmac(hmac)
        code_string = self.code_from_hash(
            truncated_hash, code_length=code_length)

        return code_string, int(period - remaining_seconds)

    def generate_hmac(self, secret_key, counter):
        from hashlib import sha1
        import hmac

        if not isinstance(secret_key, bytes):
            raise TypeError('secret_key must be a byte string')
        if not isinstance(counter, bytes):
            raise TypeError('counter must be a byte string')
        if 8 != len(counter):
            raise ValueError('counter must be 8 bytes')

        hmac = hmac.new(secret_key, counter, sha1)
        hash = hmac.digest()
        return hash

    def hash_from_hmac(self, hmac):
        if not isinstance(hmac, bytes):
            raise TypeError('hmac must be a byte string')
        if 20 != len(hmac):
            raise ValueError('hmac must be a byte string of length 20')

        offset = int("0" + hex(hmac[-1])[-1], 16)
        chunk = hmac[offset:(offset + 4)]
        truncated_hash = bytes([chunk[0] & 127]) + chunk[1:]
        return truncated_hash

    def num_to_counter(self, num):
        inum = int(num)
        if (0 > inum) or (2 ** 64 <= inum):
            raise ValueError('num')
        s_hex = hex(int(num))[2:]
        l_hex = len(s_hex)
        s_hex = ('0' * (16 - l_hex)) + s_hex
        ba_counter = bytes.fromhex(s_hex)
        return ba_counter
