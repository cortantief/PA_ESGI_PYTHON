import string
import random


def generate_random_value(length=8, digits=False):

    if digits:
        chars = string.digits
    else:
        chars = string.ascii_letters + string.digits

    return ''.join(random.choices(chars, k=length))
