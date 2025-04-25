# bloom_filter.py
import mmh3
import bitarray
import base64
from GLOBAL_DEFINE import *


class BloomFilter:

    def __init__(self, size=BF_SIZE, hash_count=BF_HASH_NUM):
        self.size = size
        self.hash_count = hash_count
        self.bit_array = bitarray.bitarray(size)
        self.bit_array.setall(0)

    def add(self, item: bytes):
        for i in range(self.hash_count):
            index = mmh3.hash(item, i) % self.size
            self.bit_array[index] = 1

    def __contains__(self, item: bytes):
        return all(self.bit_array[mmh3.hash(item, i) % self.size] for i in range(self.hash_count))

    def serialize(self):
        return base64.b64encode(self.bit_array.tobytes()).decode('utf-8')

    def export(self):
        return self.serialize().encode('utf-8')

    def count(self):
        return self.bit_array.count()

    @staticmethod
    def deserialize(data: str, size=BF_SIZE, hash_count=3):
        bf = BloomFilter(size, hash_count)
        bf.bit_array = bitarray.bitarray()
        bf.bit_array.frombytes(base64.b64decode(data))
        return bf
