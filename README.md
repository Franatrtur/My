# My
A collection of my scipts helping me develop in JS and PHP.  
Currently includes only MyCrypto in js.
I would like to point out that I'm only 14 and new to programming,  
however I'm not scared to publish this even though everyone says "don't roll your own crypto".

## MyCrypto.js
### About
A Script including extended CRC hash and my own cipher MCS (my ciphering system).  
MCS is a 128bit cipher similar to AES. Its primary purpose was just to test my programming abilities,  
although it should be highly secure, for serious things I would recommend libraries like libsodium/cryptojs.
### Usage:  
#### Simple string encryption/decryption:  
Cbc mode and Pkcs7 padding will be used by default.  
The third parameter stands for salting while deriving the key which is true by default.  
```javascript
let encrypted = MyCrypto.MCS.encrypt("message", "secret key", true);
let decrypted = MyCrypto.MCS.decrypt(encrypted, "secret key", true);
```
#### Hashing:
To simply hash a string using crc32 hash use:
```javascript
let hashed = MyCrypto.CRC.Digest("a string to hash");
```
That hash will have only one 32-bit word.  
To hash with more words and prevent collisions use extended hashing:  
`MyCrypto.CRC.Extended(string, words_count, sensitive_to_words_count)`
```javascript
let hashed = MyCrypto.CRC.Extended("a string to hash", 5, true);
//hashing the string and generating 5 words____________↑    ↑
//if we generated 4 words no words would be the same _______↑
```
a hashed words-object will be returned. Structure:
```
{
  words: /array of 32bit words/,
  toBytes: /method returning words converted to bytes/,
  toString: /method converting words to string/
}
```
Here are some things you can do with it:
```javascript
let stringed = hashed.toString(); //hex will be used by default
let stringedoctal = hashed.toString(8); //integer 2 - 36 can be used
let stringed_b64 = hashed.toString(MyCrypto.Enc.Base64); //mycrypto encoding, also just the string "Base64" could be passed
let bytes = hashed.toBytes(); //1 32bit-word is splitted to 4 bytes
```
#### Advanced encryption:  
For custom encryption parameters an encryptor must be created.  
Create an encryptor by calling the MCS.Encryptor method and passing in a settings object.  
Settings object structure (can be found at MyCrypto.MCS.settingsObj_structure):   
```
{
  mode: string - MCS provides modes "CTR", "CBC", "CFB" and not recommended "ECB",
  rounds: integer(1-32) - main encryption rounds count,
  key: byte-array(16) / (string => key derivation),
  salt: byte-array(2-16) / (integer(2-16) => count of random bytes) or (true => 8 random bytes or false => no salt),
  iv: byte-array(16) / (string => key derivation) / (true => auto from key) / (false => 16 zeros),
  encoding: {
    input: string - a property of MyCrypto.Enc, like: "Utf8"/"Latin1"/"Hex"/"Ascii"/"Base64"/"Bin",
    output: string - a property of MyCrypto.Enc, like: "Latin1"/"Hex"/"Base64"/"Bin"
  },
  padding: (string - a property of MyCrypto.MCS.Paddings, like: "Pkcs7"/"ISO_10126"/"Nulls"/"Insert") or (false => no padding, !only for modes cfb/ctr) 
}
```
put into real-life example:  
```javascript
let my_encryptor = MyCrypto.MCS.Encryptor({
  mode: "CTR",
  rounds: 9,
  key: "secret key",
  salt: true,
  iv: true,
  encoding: {
    input: "Utf8",
    output: "Base64"
  },
  padding: "Pkcs7"
});
```
These settings can be changed whenever you like under the `encryptor.settings` property.  
to encrypt data use:  
```javascript
    //encrypting string that will be converted to bytes with the encryptor input encoding
let encrypted = my_encryptor.encrypt("message");
    //encrypting raw bytes !with custom counter for ctr 173!
let encrypted_bytes = my_encryptor.encrypt([109, 101, 115, 115, 97, 103, 101], 173);
```
an MCS export object will be returned.  
```
{
  encryptor: /encryptor used/,
  usedParams /used mode, key, iv, salt and rounds/,
  data: /result in bytes/,
  encoding: /default encoding from encryptor output encoding/,
  include: /default for including salt while converting to string/,
  toString: /method convering the data to string/
}
```
Here is some stuff you can do with it:  
```javascript
let stringed = encrypted.toString(); //output encoding of the encryptor will by used, encrypted + "" will produce same result
let customstringed = encrypted.toString(MyCrypto.Enc.Hex); //custom encoding, also just the string "Hex" could be used
let stringed_without_salt = encrypted.toString("Base64", false); //used salt won't be included with the data
let usedsalt = encrypted.usedParams.salt; //salt used when encrypting the data
```
