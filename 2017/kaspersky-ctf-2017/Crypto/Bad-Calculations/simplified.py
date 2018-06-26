from random import choice
from sys import argv
from base64 import b64encode
import math

b = 22


def simplePrimaryTest(number):
    if number == 2:
       return True
    if number % 2 == 0:
        return False
    
    i = 3
    sqrtOfNumber = math.sqrt(number)
    
    while i <= sqrtOfNumber:
        if number % i == 0:
            return False
        i = i+2
        
    return True  

def dwfregrgre(x, z):
    wdef = []
    '''#for i in xrange(2, a):
         #   if (a % i) == 0:
         #       break
         '''
    for a in xrange(x, z + 1):
        #print a
        isPrime = simplePrimaryTest(a)
        if not isPrime:
            continue
        else:
            wdef.append(a)

    return wdef


def getrc(num1,num2):
    res = []
    for i in xrange(2,num1*num2+1):#int(sqrt((num1*num2)+1))):
        #for x in xrange(2,i-1):#int(sqrt(i))):
        #    if i % x ==0:
        #        break
        if not simplePrimaryTest(i):
            continue 
        else:
            res.append(i)
    return res

def sdsd(edefefef):
    fvfegve = [x for x in xrange(2, edefefef)]

    x = 2
    rrerrrr = True
    while rrerrrr:
        for i in xrange(x * x, edefefef, x):
            if i in fvfegve:
                fvfegve.remove(i)

        rrerrrr = False
        for i in fvfegve:
            if i > x:
                x = i
                rrerrrr = True
                break
    
    #print fvfegve
    return fvfegve


def swsdwd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = swsdwd(b % a, a)
        return (g, x - (b // a) * y, y)

def swsdwdwdwa(a, m):
    g, x, y = swsdwd(a, m)
    if g != 1:
        raise Exception('Oops! Error!')
    else:
        return x % m

def L(u, n):
    return (u - 1) // n


if __name__ == '__main__':
    print("Key cryptor v1.0")

    if len(argv) != 2:
        print("Start script like: python crypt.py <YourOwnPasswordString>")

    if (not str(argv[1]).startswith("KLCTF{")) or (not str(argv[1]).endswith("}")):
        print("Error! Password must starts with KLCTF")
        exit()

    p = choice(dwfregrgre(100, 1000))
    q = choice(dwfregrgre(200, 1000))

    print 'p,q : '+str(p)+', '+str(q)
    #p=11
    #q=17
    print("Waiting for encryption...")

    n = p * q
    g = None
    '''for i in xrange(n + 1, n * n):
        if ((i % p) == 0) or ((i % q) == 0) or ((i % n) == 0):
            continue

        g = i
        break

    if g is None:
        print("Error! Can't find g!")
        exit()'''
    g = (p*q)+1

    lamb = (p - 1) * (q - 1)
    mu = swsdwdwdwa(L(pow(g, lamb, n * n), n), n) % n

    #rc = sdsd(n - 1)
    rc = getrc(p,q)
    if len(rc) == 0:
        print("Error! Candidates for r not found!")
        exit()

    if p in rc:
        rc.remove(p)
    if q in rc:
        rc.remove(q)

    r = choice(rc)

    flag_content = [ord(x) for x in argv[1][6:-1]]
    #dcew = (pow(g, b, (n * n)) * pow(r, n, (n * n))) % (n * n)
    dcew = ((g**22)*(r**n))% (n*n)
    
    for i in xrange(len(flag_content)):
        '''print ("flag[i] BEFORE111: "+str(flag_content[i]))
        flag_content[i] = (((pow(g, flag_content[i], (n * n)) * pow(r, n, (n * n))) % (n * n)) * dcew) % (n * n)
        print ("flag[i] AFTER111: "+str(flag_content[i]))

        print ("flag[i] BEFORE222###: "+str(flag_content[i]))
        flag_content[i] = (L(pow(flag_content[i], lamb, (n * n)), n) * mu) % n
        print ("flag[i] AFTER222###: "+str(flag_content[i]))'''
        flag_content[i] = flag_content[i] + b

    flag_content = b64encode(bytearray(flag_content))
    print(str(flag_content)[2:-1])
