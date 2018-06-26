import z3

start_val = 21527
res = 0x8DFA

s = z3.Solver()
arr = [0]*15

def gen_constraint():
    start = '(arr[0] ^ 21527) * 2)'
    result = start
    for i in xrange(1,14):
        result = '(('+result
        result += ' ^ '+'arr[%d]) * 2)'%i

    return '('+result


for i in xrange(15):
    arr[i] = z3.BitVec('x_%d' % i, 32)
    s.add(arr[i] >60)
    s.add(arr[i] <=96)

gen_constraint()
s.add(eval(gen_constraint()) % 0x10000 == res) # Hacking this part to make it easier for me to add the constraint :P

s.check()
s.model()
print 'The password is:\n%s' % (''.join([chr(int(str(s.model()[arr[i]]))) for i in xrange(14)]).replace(' ',''))
