import random


class UTIL:
    def __init__(self):
        pass 

    def random_id(self, s_len:int)->str:
        return "".join(random.choices(string.ascii_letters + string.digits, k=s_len))
