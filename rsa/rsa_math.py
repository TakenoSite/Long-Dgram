import primes

class MATH:
    def __init__(self):
        pass 
    
    def modular_exp(self, a, b, n):
        res = 1
        while b != 0:
            if b & 1 != 0:
                res = (res * a) % n
            a = (a * a) % n
            b = b >> 1
            
        return res


    def modular_mult(self, a, b, mod):
        if a == 0:
            return 0

        product = a * b 
        if product / a == b:
            return product % mod 

        if a & 1:
            product = self.modular_mult((a>>1), b, mod)
            if (product << 1) > product:
                return (((product << 1) % mod) + b) % mod

        product = self.modular_mult((a >> 1), b, mod)
        if ((product << 1) > product):
            return (product << 1) % mod

        sum_n = 0
        while b > 0:
            if b & 1:
                sum_n = (sum_n + a) % mod
            a = (2 * a) % mod
            b >>= 1
        return sum_n


    def gcd(self, a, b):
        while a != 0:
            c = a
            a = b % a
            b = c 
        
        return b


    def ext_euclid(self, a, b):
        x = 0
        y = 1
        u = 1
        v = 0
        gcd = b 
        
        m = 0
        n = 0 
        q = 0 
        r = 0 

        while a != 0:            
            q   = gcd//a
            r   = gcd % a
            m   = x-u*q
            n   = y-v*q
            gcd = a
            a   = r
            x   = u 
            y   = v 
            u   = m 
            v   = n
            
            #print(q,r,m,n,gcd,a,x,y,u,v) # debug 
        #print("ExtEuclid : ", y) #debug 
        return  y

    def generate_prime(self, gen_len:int, bit_size:int)->list:
        big_primes_list = []
        
        for _ in range(gen_len):
            res = primes.generate_prime(bit_size)
            big_primes_list.append(res)

        return big_primes_list

