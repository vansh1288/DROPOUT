with open(r"C:\DROP\host_server\protocol_bridge.py", "rb") as f:
    content = f.read()
content = content.replace(b'b"" * length', b'b"\\x00" * length')
with open(r"C:\DROP\host_server\protocol_bridge.py", "wb") as f:
    f.write(content)
print("Fixed protocol_bridge.py AES-CTR bug")