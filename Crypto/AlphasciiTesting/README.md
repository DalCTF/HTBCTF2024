# Alphascii Testing

## Analysis

In this problem we are given the [source code](./server.py) to a server to be accessed using `netcat`. In this server we have three options: login, register, and exit. The server claims to be using `MD5` to secure the credentials and that they are sure this is very secure. Any option passed to the server needs to be written in `JSON` format, which has no real impact on the problem, but is an added step to solving this.

## Solution

After analyzing the code, we will notice that for us to select one of the options on the menu, we need to send a `JSON` with the `option` attribute set to the element we want. Despite having numbers in the options (e.g. `[1] Login`), those don't mean anything. If we want to perform any of the actions on the menu, we need to send the following:

```json
{"option": "login"}     // Login
{"option": "register"}  // Register
{"option": "exit"}      // Exit
```

In the case of the `Login` and `Register` options, we will then be prompted for the credentials, which will need to be send as follows:

```json
{"username": "johndoe", "password": "123456"}
```

If we look at the code for the `Register` action, we will see that the user is registered by storing the credentials on a dictionary. In this case, the dictionary key is the `username`, while the value is a tuple with the `MD5` hash of the `username`, and the password in plain text.

On the `Login` action, we will see that the code iterates over every registered user checking if any matches the `password` as well as the `MD5` hash of the username we provided. If it does match, then the code checks if the **actual** username matches the one we provided. If they do, we simply get a login message. However, if they don't, we are presented the flag.

In a nuthsell, our objective is to register a user and, after, attempt to login with a different username that will cause a hash collision with the registered one.

Our first step is to find two strings that generate the same `MD5` hash. A quick search search online reveals that, given the strings:

```python
A = TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak
B = TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak
                         ^ # That's where they differ
```

Their `MD5` hashes collide:

```python
md5(A) = md5(B) = "faad49866e9498fc1719f5289e7a0269"
```

Therefore, we can provide the system with the following steps:

```json
{"option": "register"}
{
    // This is string A
    "username": "TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak", 
    "password":"password"
} 
{"option": "login"}
{
    // This is string B
    "username": "TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak", 
    "password":"password"
} 
```

An we will be greeted with the flag.