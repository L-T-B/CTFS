# UWUCTF: A Zeroday In Bash-Quote
## Intoduction
On first load of the website we can see some text and a hyperlink:

![image](https://github.com/L-T-B/CTFS/assets/62217895/5bc1db36-e37b-4411-be52-23eafe0796f2)

So following the link we can find a directory listing of texts to "uwuify".
```txt
texts avali to uwuify: 
cowspeak.txt
java.txt
linux_memory_barriers.txt
linux_memory_faq.txt
zenofpython.txt

Use /uwuify?src=<text file name> to uwuify a text file!
```
A quick look into the source and challenge description reveals the goal. Leaking the flag in the application directory.
And a look in the index.js also displays the limitations of our attack:
```js
if(req.query.src.includes("..") || req.query.src.includes("./") || req.query.src.startsWith("/") || req.query.src.startsWith("-")){
      res.send("no hacking >:(");
      res.end();
      return;
    }
```
So we need a path traversal not containting `..`, `./` as well as not starting with `/` and `-`.
This all leads into the sink of the dangerous function exec:
```js
let cmd = "cat " + quote([req.query.src]) + " | " + uwuifierPath;
    exec(cmd, {
      cwd: textsDir
    }, (err, stdout, stderr) => {
      res.send(stdout + stderr);
      res.end();
    });
```

## First Bug

After setting up a local instance of the challenge we created a fuzzer to test the application. If you turn to fuzzing always use a local setup if possible, else you will probably DOS the server!

Our first test tried to find some characters which would be ignored by bash. 
So something to the lines of `{target}/etc/password` which would be interpreted as `/etc/passwd`. For which we just looped over all the characters in the range of 0x0-0xfff.

Through this setup we found two interesting finds. 

First the `~` character: This was special character wasn't escaped by the appliaction and resulted in bash interpreting it as the home directory. With this path traversal it was possible to "uwuify" the flag which was conveniently in `~/app/flag.txt`.

This gave us 

`amateuwsctf{so_wmao_this_fwag_is_gonna_be_a_wot_wongew_than_most_fwag_othew_fwags_good_wuck_have_fun_decoding_it_end_of_fwag}`. 

This can be "unuwuifyed" but there's an other solution:

## Second Bug

I talked about two intersting finds. The second character we deemed intersting was a nullbyte (`\x00` or `%00`). This resulted in the application hanging. After some debugging we found that everything after the nullbyte got ignored.
Which explained the hanging of the application, because `cat (nullbyte)/etc/password | ./../uwuify` was being parsed by bash as `cat `. By abusing that nullbyte we were able to stop the "uwuifying" by using a path like `~/app/flag.txt%00` (https://uwuasaservice.amt.rs/uwuify?src=~/app/flag.txt%00). 

This gave us the flag: `amateursCTF{so_lmao_this_flag_is_gonna_be_a_lot_longer_than_most_flag_other_flags_good_luck_have_fun_decoding_it_end_of_flag}`

## Here Ends The Challenge
Thanks to the author smashmaster for this cool challenge!

And thank you for reading :)


------------------------------


## Appendix Third Bug

While fuzzing we also got the error `/bin/sh: 1: Syntax error: Unterminated quoted string` and found it was possible to crash the application by using an whitespace character (Space, Newline, Tab...) followed by a nullbyte. 

The reason behind this is actually quite simple. The whitespace character would result in quotes being added to properly encode the command. So `abc(space)abc` would become `'abc(space)abc'`. 

Now if we add a nullbyte, you probably see where this is going: `(space)(nullbyte)` gets encoded to `'(space)(nullbyte)'` which then gets parsed by bash as `'(space)` which is not a valid bash.

## The Zeroday Vulnerabilty

I would make the case that removing all following commands is probably not a very severe vulnerabilty it can lead to some information disclosures. 
Let's take the following code as an example:
```js
let cmd = "cat " + quote([req.query.logfile]) + " | grep VERSION:";
exec(cmd, {}, (err, stdout, stderr) => {
  res.send(stdout + stderr);
  res.end();
});
```
An attacker could send something like `https://app.com/log?logfile=sensitive.log%00` which could resullt in information disclosure and thus I would propose all nullbytes being encoded or removed by bash-quote.
