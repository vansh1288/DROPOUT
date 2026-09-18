with open(r'C:\DROP\host_server\protocol_bridge.py', 'rb') as f:
    content = f.read()

# Search for the pattern in different forms
patterns = [
    b'b"" * length',
    b'b\'\' * length',
    b'b""*length',
    b'b\'\'*length',
    b'update(b""',
    b'update(b\'\')',
]

for pat in patterns:
    idx = content.find(pat)
    if idx >= 0:
        print(f'Found "{pat}" at {idx}: {content[idx:idx+30]}')
    else:
        print(f'Not found: {pat}')

# Also search for "update" followed by something
idx = content.find(b'update')
if idx >= 0:
    print(f'\nFound "update" at {idx}: {content[idx:idx+50]}')