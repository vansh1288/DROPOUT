with open(r'C:\DROP\host_server\protocol_bridge.py', 'r') as f:
    content = f.read()
content = content.replace('b"" * length', 'b"\\x00" * length')
with open(r'C:\DROP\host_server\protocol_bridge.py', 'w') as f:
    f.write(content)
print('Fixed')