import http.client, uuid, os

file_path = 'test_upload.txt'
with open(file_path, 'wb') as f:
    f.write(b'Test upload payload')

boundary = uuid.uuid4().hex
body = bytearray()
body.extend(b'--' + boundary.encode() + b"\r\n")
body.extend(b'Content-Disposition: form-data; name="file"; filename="test_upload.txt"\r\n')
body.extend(b'Content-Type: text/plain\r\n\r\n')
with open(file_path, 'rb') as f:
    body.extend(f.read())
body.extend(b"\r\n--" + boundary.encode() + b"--\r\n")

headers = {
    'Content-Type': 'multipart/form-data; boundary=' + boundary,
    'Content-Length': str(len(body))
}

conn = http.client.HTTPConnection('127.0.0.1', 5000, timeout=10)
try:
    conn.request('POST', '/vault/files/upload', body, headers)
    res = conn.getresponse()
    print('STATUS', res.status)
    print(res.read().decode())
except Exception as e:
    print('ERROR', e)
finally:
    conn.close()
