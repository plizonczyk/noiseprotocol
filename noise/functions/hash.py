import abc


class Hash(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def fn(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def hashlen(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def blocklen(self):
        raise NotImplementedError

    @abc.abstractmethod
    def hash(self, data):
        raise NotImplementedError


def hkdf(chaining_key, input_key_material, num_outputs, hmac_hash_fn):
    # Sets temp_key = HMAC-HASH(chaining_key, input_key_material).
    temp_key = hmac_hash_fn(chaining_key, input_key_material)

    # Sets output1 = HMAC-HASH(temp_key, byte(0x01)).
    output1 = hmac_hash_fn(temp_key, b'\x01')

    # Sets output2 = HMAC-HASH(temp_key, output1 || byte(0x02)).
    output2 = hmac_hash_fn(temp_key, output1 + b'\x02')

    # If num_outputs == 2 then returns the pair (output1, output2).
    if num_outputs == 2:
        return output1, output2

    # Sets output3 = HMAC-HASH(temp_key, output2 || byte(0x03)).
    output3 = hmac_hash_fn(temp_key, output2 + b'\x03')

    # Returns the triple (output1, output2, output3).
    return output1, output2, output3