with open(r'C:\DROP\host_server\protocol_bridge.py', 'rb') as f:
    data = f.read()
data = data.replace(b'\x00', b'')
with open(r'C:\DROP\host_server\protocol_bridge.py', 'wb') as f:
    f.write(data)
print('Fixed')