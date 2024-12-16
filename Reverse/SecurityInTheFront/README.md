# Security In The Front

## Analysis

The problem gives us a single [`index.html`](Source/index.html) file. If rendered, it has a login form asking for a guard name and an access code.

## Solution

By analyzing the code for the page, we will notice that the validation of the login credentials are handled in JavaScript directly on the client. The function `checkCredentials` is written on a single line and is obfuscated. This is where the solution lies, and it's where we will focus our efforts.

By running the line through a [JS Beautifier](https://beautifier.io/) we will have a better idea of the code. First we notice some single-letter variables (c, i, a, o p, etc) which hold the value of prototype functions of known classes. Our first step is to replace all instances of these variables for their values. We will then notice that there is a big `if` condition with multiple values inside, eventually reaching a call to `.reduce()`. This means that each element of the outermost array is going to be sent to the function along with the current value, starting with `true`. The function used is `(e, t) => e && n.apply(undefined, t)`, where `e` is the current value of the reduction, and `t` is the element of the array. The element of the array is send to function `n`, which is in itself a `.reduce()`. This element `t` is going to be called the *block* from this point forward. The outermost array is a collection of blocks, and each call of `n` handles a single block.

The function `n` has three parameters which will be taken from the block: the first is a list of functions, the second is a list of arguments, and the third is a value. The function essentially applies the functions of the first parameter, `e`, in sequence using the respective parameters, using the value as the current "context". For example, the first block is the following:

```javascript
[String.prototype.split, Array.prototype.map, f, h],
[
    [""], 
    [e => -1 == Array.prototype.indexOf(c2, e) ? e : c1[Array.prototype.indexOf(c2, e)]],
    [
        ["n", "q", "z", "v", "a"]
    ],
    [0]
], 
access_user
```

This will apply the function `String.prototype.split` to the value (`access_user.split()`) with the parameter `""`, meaning that it will break the string into its individual characters. Next, it will apply the function `e => -1 == Array.prototype.indexOf(c2, e) ? e : c1[Array.prototype.indexOf(c2, e)]` to each character using `.map()`. This function finds the character inside the `c2` variable and, if it exists, replaces it with the character at the same index in `c1`. Next, it uses function `f` to compare the current value to that of `["n", "q", "z", "v", "a"]`. Function `f` will give us `-1`, `0`, or `1` depending on the result of the comparison. Equality is represented by `0`. Finally, it uses function `h` to test if our final value is equal to `0`. If it is, the final value of the block is `true`.

It is our job to reverse every step of this block, which is essentially reversing the translation made in the second step where every character from `c2` became its counterpart on `c1`. We will do this by finding `n` in `c1` and checking its counterpart in `c2`, which is `a`. The same for `q`, which is `d`, `z` becomes `m`, `v` becomes `i`, and `a` becomes `n`. With that, we conclude that the expected value for `access_user` is `admin`.

We now have another 8 blocks to reverse to find clues about the `access_code`. Explanations will be summarized for brevity:

```javascript
[String.prototype.slice, String.prototype.repeat, String.prototype.split, Array.prototype.map, Array.prototype.filter, f, h],
[
    [0, 4],
    [3],
    [""],
    [e => -1 == Array.prototype.indexOf(c2, e) ? e : c1[Array.prototype.indexOf(c2, e)]],
    [(e, t) => t % 3 == 1],
    [
        ["G", "U", "{", "O"]
    ],
    [0]
], access_code
```

In this block we get the first 4 characters of the code, repeat it 3 times, split into the individual characters, perform the translation from `c2` to `c1`, get the character at every index where `index % 3 == 1` (indexes 1, 4, 7, and 10), compare it to `["G", "U", "{", "O"]`, and make sure they are the same.

Reversing this block tells us that the first 4 characters of the access code are `HTB{`.

```javascript
[String.prototype.slice, function () {
    return encodeURI(this)
}, String.prototype.slice, function (e) {
    return parseInt(this, e)
}, function (e) {
    return this ^ e
}, h],
[
    [-1],
    [],
    [-2],
    [16],
    [96],
    [29]
], access_code
```

In this block we get the last character of the code, encode it using URI encoding, get the last 2 characters of that (essentially stripping the `%` part of the result), parse it as an integer using base 16, perform an `XOR` with `96`, and compare it to `29`.

Reversing this block tells us that the last character of the code is `}`.

> (At this point we just figured out the obvious, that is, that the flag starts with `HTB{` and ends in `}`, but its reassuring to see that our process makes sense)

```javascript
[String.prototype.split, Array.prototype.reduce, h],
[
    [""], 
    [e => e + e, 1],
    [16777216]
], access_code
```

This block splits all the characters of the code and performs a reduce adding the value of each character to the initial value of `1` and comparing it to `16777216`. This means that the sum of all characters in the result is `16777215` (subtract the initial `1`).

```javascript
[String.prototype.repeat, String.prototype.split, Array.prototype.map, Array.prototype.reduce, h],
[
    [21], 
    [""], 
    [e => n1[Array.prototype.indexOf(n2, e)]],
    [(e, t) => e + h.apply(t, [8]), 0],
    [63]
], access_code
```

This block repeats the code `21` times and splits it into individual characters. It then finds the index of each character in the `n2` array and replaces it with its counterpart in `n1`. It then adds the value of the equality between each value and `8`. In JavaScript, `true` has the value of `1` and `false` the value of `0`, meaning that it will add `1` for each value `8` it finds. Finally, it compares it to `63`.

The value in `n2` that will result in `8` in `c1` is the character `3`. Since we repeated the code `21` times, this blocks says that our original code contains `3` (`63/21`) characters `3`.

```javascript
[String.prototype.split, Array.prototype.filter, Array.prototype.map, Array.prototype.reverse, Array.prototype.join, h],
[
    [""], 
    [(e, t) => ~Array.prototype.indexOf([4, 11, 13, 14, 16, 17, 20, 22], t)],
    [e => c1[Array.prototype.indexOf(c2, e)]], // FDPWCHKR
    [],
    ["-"], // SQCJPUXE
    ["E-X-U-P-J-C-Q-S"]
], access_code
```

This block splits the code into individual characters and then removes all the elements that are not on indexes `4, 11, 13, 14, 16, 17, 20, and 22`. It then performs the replacement from `c2` to `c1`, reverses the array, joins the elements using `-`, and compares the result to `E-X-U-P-J-C-Q-S`.

Reversing this block tells us that the code, from the beginning to index `22`, fits the pattern `____F______D_PW_CH__K_R` (where `_` means unknown values).

```javascript
[function () { return Array.from(this) }, f, h],
[
    [],
    [
        ["_"]
    ],
    [0]
], new Set(
    n(
        [String.prototype.slice, String.prototype.split, Array.prototype.reverse, Array.prototype.filter], 
        [
            [12, 16],
            [""],
            [],
            [(e, t) => ~Array.prototype.indexOf([0, 3], [t])]
        ], access_code)
    )
]
```

This block converts the value into an array and compares it to `["_"]`, meaning that what really matters here is what is inside of the `Set()` call, which is in itself another block. In that block, it takes the values from indexes `12, 13, 14, and 15` from the code, splits into individual characters, reverses, and removes all values but for the ones in indexes `0` and `3`. This would be the equivalent of keeping the values from positions `12` and `15` from the original code. Since this is a `Set`, the same value would not exist twice, which explains how a set with two elements can become an array with a single element. This means that both characters are the same and are both `_`.

```javascript
[String.prototype.split, Array.prototype.reverse, Array.prototype.filter, function () {
    return this.slice(2, this.length).concat(this.slice(0, 2))
}, Array.prototype.reverse, Array.prototype.join, h],
[
    [""], 
    [],
    [(e, t) => ~Array.prototype.indexOf([18, 13, 4, 16, 15], [t])],
    [],
    [],
    [""],
    ["ncrnt"]
], access_code
```

This block splits the code into individual characters, reverses it, removes all elements but the ones on indexes `4, 13, 15, 16, and 18`, takes the two first elements and places them at the end, reverses the array, joins it back into a string, and compares it to `ncrnt`.

Reversing this block gives us that the code follows the pattern `r_nt_n________c____` from the end (we are sure that there are 4 characters between the end of the string and `c`, but not how many there are before `r`).

```javascript
[String.prototype.charAt, h],
[
    [6],
    ["0"]
], access_code
```

Our final block tells us that the character at index `6` is the character `0`.

With that, we can join all the hints to determine the code:

```
0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20 21 22 23
H  T  B  {  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
.  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  }
.  .  .  .  F  .  .  .  .  .  .  D  .  P  W  .  C  H  .  .  K  .  R  .
.  .  .  .  .  .  .  .  .  .  .  .  _  .  .  _  .  .  .  .  .  .  .  .
.  .  .  .  .  r  .  n  t  .  n  .  .  .  .  .  .  .  .  c  .  .  .  .
.  .  .  .  .  .  0  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .

H  T  B  {  F  r  0  n  t  .  n  D  _  P  W  _  C  H  .  c  K  .  R  }
```

The three missing characters are replaced by the three characters `3` that we know must exist, which gives us the final flag:

`HTB{Fr0nt3nD_PW_CH3cK3R}`