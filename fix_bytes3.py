with open(r'C:\DROP\host_server\protocol_bridge.py', 'rb') as f:
    content = f.read()

# Find the pattern
idx = content.find(b'b"" * length')
if idx >= 0:
    print(f'Found at {idx}')
    content = content[:idx] + b'b"\\x00" * length' + content[idx + len(b'b"" * length'):]
    with open(r'C:\DROP\host_server\protocol_bridge.py', 'wb') as f:
        f.write(content)
    print('Fixed')
else:
    print('Pattern not found, searching...')
    for i in range(len(content) - 15):
        if content[i:i+2] == b'b' and content[i+1] == ord('"'):
            print(f'At {i}: {content[i:i+20]}')