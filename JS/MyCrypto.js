/*
MyCrypto.js v1.1 by FranaTrtur
My/MyCrypto.js
includes 
	ciphering system MCS (My Ciphering System)
	and extended crc hashing system 
*/

/*MIT LICENSE (My/LICENSE.txt)

Copyright (c) 2019 František Artur Čech
Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

MyCrypto = {
	MCS: {},
	CRC: {},
	Enc: {},
	info:{
		version: "1.1", 
		author: "František Artur Čech (FranaTrtur) - CZ"
	}
};

MyCrypto.Enc = {
	Utf8: {
		parse: function(string){
			if(typeof TextEncoder == "function")
				return Array.from(new TextEncoder("utf-8").encode(string));
			var escaped = unescape(encodeURIComponent(string));
			var bytes = [];
			for(var char = 0; char < escaped.length; char++)
				bytes[char] = escaped.charCodeAt(char);
			return bytes;
		},
		stringify: function(bytes){
			if(typeof TextDecoder == "function")
				return new TextDecoder("utf-8").decode(new Uint8Array(bytes));
			var string = "";
			for(var byte = 0; byte < bytes.length; byte++)
				string += String.fromCharCode(bytes[byte]);
			return decodeURIComponent(escape(string));
		}
	},
	Hex: {
		parse: function(string){
			var bytes = [];
			for(var hxcode = 0; hxcode < string.length; hxcode += 2)
				bytes.push(parseInt(string.charAt(hxcode) + string.charAt(hxcode + 1), 16));
			return bytes;
		},
		stringify: function(bytes){
			var string = "";
			for(var byte = 0; byte < bytes.length; byte++)
				string += ("00" + bytes[byte].toString(16)).substr(-2);
			return string;
		}
	},
	Bin: {
		parse: function(string){
			var bytes = [];
			for(var bincode = 0; bincode < string.length; bincode += 8)
				bytes.push(parseInt(string.slice(bincode, bincode + 8), 2));
			return bytes;
		},
		stringify: function(bytes){
			var string = "";
			for(var byte = 0; byte < bytes.length; byte++)
				string += ("00000000" + bytes[byte].toString(2)).substr(-8);
			return string;
		}
	},
	Base64: {
		parse: function(string){
			var bytes = [];
			var atobed = window.atob(string);
			for(var char = 0; char < atobed.length; char++)
				bytes[char] = atobed.charCodeAt(char);
			return bytes;
		},
		stringify: function(bytes){
			var string = "";
			for(var byte = 0; byte < bytes.length; byte++)
				string += String.fromCharCode(bytes[byte]);
			return window.btoa(string);
		}
	},
	Ascii: {
		parse: function(string){
			var compressed = "";
			var bytes = [];
			for(var char = 0; char < string.length; char++)
				compressed += ("0000000" + string.charCodeAt(char).toString(2)).slice(-7);
			for(var bits8 = 0; bits8 < compressed.length; bits8 += 8)
				bytes.push(parseInt(compressed.substr(bits8, 8), 2));
			return bytes;
		},
		stringify: function(bytes){
			var copied = bytes.slice(0);
			var decompressed = "";
			var string = "";
			var bits7 = [];
			for(var byte = 0; byte < copied.length; byte ++){
				if(byte == copied.length - 1){
					while((decompressed.length + copied[copied.length - 1].toString(2).length) % 7 !== 0)
						decompressed += "0";
					decompressed += copied[copied.length - 1].toString(2);
					break;
				}
				decompressed += ("00000000" + copied[byte].toString(2)).slice(-8);
			}
			for(var chunk7 = 0; chunk7 < decompressed.length; chunk7 += 7)
				bits7.push(parseInt(decompressed.substr(chunk7, 7), 2));
			for(var charidx = 0; charidx < bits7.length; charidx++)
				string += String.fromCharCode(bits7[charidx]);
			return string;
		}
	},
	Latin1: {
		parse: function(string){
			var bytes = [];
			for(var char = 0; char < string.length; char++)
				bytes[char] = string.charCodeAt(char) % 256;
			return bytes;
		},
		stringify: function(bytes){
			var string = "";
			for(var byte = 0; byte < bytes.length; byte++)
				string += String.fromCharCode(bytes[byte]);
			return string;
		}
	},
	Words: {
		to: function(bytes){
			var words = [];
			for(var byte = 0; byte < bytes.length; byte += 4)
				words.push((bytes[byte] << 24 | bytes[byte + 1] << 16 | bytes[byte + 2] << 8 | bytes[byte + 3]) >>> 0);
			return words;
		},
		from: function(words){
			var bytes = [];
			for(var word = 0; word < words.length; word++)
				bytes = bytes.concat([words[word] << 24 >>> 24, words[word] << 16 >>> 24, words[word] << 8 >>> 24, words[word]>>> 24]);
			return bytes;
		}
	}
};


MyCrypto.MCS.Core = {};
MyCrypto.MCS.Paddings = {};
MyCrypto.MCS.Modes = {};

MyCrypto.MCS.Core.S_box = 
  [0xc1, 0xef, 0xcd, 0xf2, 0x8d, 0xe1, 0x1b, 0x83, 0xdd, 0x69, 0x8e, 0xda, 0xb5, 0x2d, 0x90, 0xa5,
   0x5a, 0xe3, 0x09, 0x2a, 0xca, 0x95, 0xa2, 0x19, 0x35, 0x0b, 0x32, 0x65, 0x57, 0x73, 0xbb, 0x10,
   0xc4, 0x52, 0x74, 0x2f, 0xd7, 0x26, 0x03, 0xc3, 0x6f, 0xd9, 0x7f, 0x33, 0x3a, 0xd0, 0xdf, 0xa3,
   0x1e, 0x0d, 0xac, 0xfd, 0xc9, 0xbc, 0x8f, 0x66, 0x72, 0xe8, 0x81, 0x89, 0x05, 0x2b, 0x13, 0xcb,
   0xab, 0xa8, 0x30, 0x38, 0x76, 0x7b, 0x3d, 0xf4, 0x7c, 0x1d, 0x5e, 0xc2, 0xea, 0x9a, 0xaf, 0xfa,
   0x14, 0xa9, 0xc6, 0xb7, 0xa4, 0xb9, 0xd5, 0x96, 0x3f, 0x06, 0x1f, 0x79, 0xa7, 0x97, 0x87, 0x7d,
   0x84, 0xd6, 0x6d, 0x99, 0x08, 0x58, 0xae, 0xbe, 0x71, 0x8c, 0x24, 0xc8, 0xb6, 0x59, 0x25, 0xbd,
   0xc0, 0x28, 0xd8, 0xb4, 0x44, 0x54, 0xb3, 0x70, 0x37, 0x20, 0x67, 0x46, 0x93, 0xe4, 0xde, 0x0c,
   0x17, 0x4b, 0xdb, 0xf7, 0xc7, 0x8a, 0x31, 0x8b, 0x53, 0xfe, 0xdc, 0x6e, 0x16, 0x1c, 0xbf, 0x4f,
   0xec, 0x02, 0x78, 0x22, 0x92, 0xf1, 0xe6, 0x68, 0x86, 0xb8, 0x11, 0xfb, 0x23, 0xeb, 0x6c, 0x0e,
   0xcf, 0x9d, 0x27, 0x6a, 0x39, 0x91, 0x5b, 0x49, 0x36, 0xf0, 0xad, 0x82, 0xf5, 0x7a, 0xf8, 0xb0,
   0x3c, 0xaa, 0x40, 0x5d, 0x34, 0xfc, 0x1a, 0x01, 0x9e, 0xba, 0x85, 0x07, 0xd1, 0xee, 0x98, 0x7e,
   0x4a, 0x18, 0xd3, 0x80, 0x56, 0x29, 0x4e, 0xb2, 0xf9, 0x2e, 0x94, 0xd4, 0xce, 0x4d, 0xf3, 0x42,
   0x41, 0x62, 0x9f, 0x45, 0x00, 0xa6, 0x12, 0xcc, 0x88, 0x50, 0xd2, 0x43, 0x0a, 0xc5, 0xff, 0x3b,
   0xf6, 0x2c, 0x3e, 0x64, 0x48, 0x04, 0xa1, 0x21, 0x5c, 0x51, 0xe0, 0x9b, 0x0f, 0x77, 0x61, 0x4c,
   0xed, 0xe9, 0x75, 0x5f, 0xe5, 0x55, 0xe7, 0x15, 0x60, 0xb1, 0x9c, 0x47, 0x6b, 0x63, 0xe2, 0xa0];

MyCrypto.MCS.Core.SubBytes = function(state){
	var newstate = [];
	for(var byte = 0; byte < state.length; byte++)
		newstate[byte] = MyCrypto.MCS.Core.S_box[state[byte]];
	return newstate;
};
MyCrypto.MCS.Core.SubBytesInv = function(state){
	var newstate = [];
	for(var byte = 0; byte < state.length; byte++)
		newstate[byte] = MyCrypto.MCS.Core.S_box.indexOf(state[byte]);
	return newstate;
};

MyCrypto.MCS.Core.Shuffle = function(state){
	return [state[0x9], state[0x4], state[0xd], state[0x8],
			state[0xf], state[0xc], state[0x0], state[0xe],
			state[0x2], state[0x7], state[0x1], state[0x5],
			state[0xa], state[0xb], state[0x3], state[0x6]];
};
MyCrypto.MCS.Core.ShuffleInv = function(state){
	return [state[0x6], state[0xa], state[0x8], state[0xe],
			state[0x1], state[0xb], state[0xf], state[0x9],
			state[0x3], state[0x0], state[0xc], state[0xd],
			state[0x5], state[0x2], state[0x7], state[0x4]];
};

MyCrypto.MCS.Core.Permute = function(state, salt){
	salt = Array.isArray(salt) ? salt : [0x5a, 0xf5, 0xa5, 0xc2];
	var rot = function(byte, shift){return (byte << shift | byte >> (8 - shift)) << 24 >>> 24;};
	var newstate = [];
	var temp0, temp1, temp2, temp3;
	for(var i = 0; i < state.length; i += 4){
		temp0 = state[i] ^ state[i + 3] ^ salt[i % salt.length];
		temp1 = state[i + 1] ^ temp0 ^ salt[(i + 1) % salt.length];
		temp2 = state[i + 2] ^ temp1 ^ salt[(i + 2) % salt.length];
		temp3 = state[i + 3] ^ temp2 ^ salt[(i + 3) % salt.length];
		newstate[i + 3] = temp3 ^ rot(temp0, 3);
		newstate[i + 2] = temp2 ^ rot(newstate[i + 3], 3);
		newstate[i + 1] = temp1 ^ rot(newstate[i + 2], 3);
		newstate[i] = temp0 ^ rot(newstate[i + 1], 3);
	}
	return newstate;
};
MyCrypto.MCS.Core.PermuteInv = function(state, salt){
	salt = Array.isArray(salt) ? salt : [0x5a, 0xf5, 0xa5, 0xc2];
	var rot = function(byte, shift){return (byte << shift | byte >> (8 - shift)) << 24 >>> 24;};
	var newstate = [];
	var temp0, temp1, temp2, temp3;
	for(var i = 0; i < state.length; i += 4){
		temp0 = state[i] ^ rot(state[i + 1], 3);
		temp1 = state[i + 1] ^ rot(state[i + 2], 3);
		temp2 = state[i + 2] ^ rot(state[i + 3], 3);
		temp3 = state[i + 3] ^ rot(temp0, 3);
		newstate[i + 3] = temp3 ^ temp2 ^ salt[(i + 3) % salt.length];
		newstate[i + 2] = temp2 ^ temp1 ^ salt[(i + 2) % salt.length];
		newstate[i + 1] = temp1 ^ temp0 ^ salt[(i + 1) % salt.length];
		newstate[i] = temp0 ^ newstate[i + 3] ^ salt[i % salt.length];
	}
	return newstate;
};

MyCrypto.MCS.Core.ApplyKey = function(data, key){
	var newdata = data.slice(0);
	for(var byte = 0; byte < data.length; byte++)
		newdata[byte] ^= key[byte % key.length];
	return newdata;
};

MyCrypto.MCS.Core.AddKey = function(data, key){
	var newdata = [];
	for(var byte = 0; byte < data.length; byte++)
		newdata[byte] = (data[byte] + key[byte % key.length]) % 256;
	return newdata;
};
MyCrypto.MCS.Core.SubKey = function(data, key){
	var newdata = [];
	for(var byte = 0; byte < data.length; byte++)
		newdata[byte] = (data[byte] - key[byte % key.length] + 256) % 256;
	return newdata;
};

MyCrypto.MCS.Core.ExpandKey = function(key, iter){
	if(typeof iter != "number")
		iter = 0;
	var my_rcon = [0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xf0, 0x1b, 0x3b, 0x5b, 0x9b];
	var lastword = key.slice(-4);
	var rot_word = 
	   [MyCrypto.MCS.Core.S_box[lastword[3]] ^ my_rcon[iter % my_rcon.length] ^ key[0],
		MyCrypto.MCS.Core.S_box[lastword[0]] ^ key[1],
		MyCrypto.MCS.Core.S_box[lastword[1]] ^ key[2],
		MyCrypto.MCS.Core.S_box[lastword[2]] ^ key[3]];
	var newkey = rot_word;
	for(var byte = 4; byte < 16; byte++)
		newkey[byte] = newkey[byte - 4] ^ key[byte];
	return newkey;
};

MyCrypto.MCS.Core.CompressKey = function(key){
	return [
		key[0x6] ^ key[0xa],
		key[0x8] ^ key[0xe],
		key[0x1] ^ key[0xb],
		key[0xf] ^ key[0x3],
		key[0x9] ^ key[0x0],
		key[0xc] ^ key[0x2],
		key[0x5] ^ key[0xd],
		key[0x7] ^ key[0x4]
	];
};

MyCrypto.MCS.Core.EncryptRound = function(data, key){
	return MyCrypto.MCS.Core.ApplyKey(MyCrypto.MCS.Core.Permute(MyCrypto.MCS.Core.Shuffle(MyCrypto.MCS.Core.SubBytes(data)), MyCrypto.MCS.Core.CompressKey(key)), key);
};
MyCrypto.MCS.Core.DecryptRound = function(data, key){
	return MyCrypto.MCS.Core.SubBytesInv(MyCrypto.MCS.Core.ShuffleInv(MyCrypto.MCS.Core.PermuteInv(MyCrypto.MCS.Core.ApplyKey(data, key), MyCrypto.MCS.Core.CompressKey(key))));
};

MyCrypto.MCS.GenerateBlock = function(seed, nbytes){
	nbytes = typeof nbytes == "number" ? nbytes : 16;
	return MyCrypto.CRC.Extended(seed + "", Math.ceil(nbytes / 4), false).toBytes().slice(0, nbytes);
};

MyCrypto.MCS.DeriveKey = function(str, salt, iter, nbytes){
	nbytes = typeof nbytes == "number" ? nbytes : 16;
	iter = typeof iter == "number" ? iter : 128;
	return MyCrypto.CRC.Extended(str + MyCrypto.Enc.Latin1.stringify(salt), iter, true).toBytes().slice(-nbytes);
};

MyCrypto.MCS.ParseKey = function(input, type){
	if(MyCrypto.Enc.hasOwnProperty(type))
		return MyCrypto.Enc[type].parse(input);
	else if(typeof type.parse != "undefined")
		return type.parse(input);
	else
		return input;
};

MyCrypto.MCS.RandomBytes = function(leng){
	leng = typeof leng == "number" ? leng : 16;
	var key = [];
	for(var byte = 0; byte < leng; byte++)
		key.push(Math.floor(Math.random() * 256));
	return key;
};

MyCrypto.MCS.Schedule = function(key, rounds){
	var keys = [key.slice(0)];
	rounds = typeof rounds != "number" ? 9 : rounds;
	for(var round = 0; round < rounds; round++)
		keys.push(MyCrypto.MCS.Core.ExpandKey(keys[keys.length - 1], round));
	return keys;
};

MyCrypto.MCS.Format = function(stream, cut){
	cut = typeof cut == "number" ? cut : 16;
	var blocks = [];
	for(var bytesx = 0; bytesx < stream.length; bytesx += cut)
		blocks.push(stream.slice(bytesx, bytesx + cut));
	return blocks;
};
MyCrypto.MCS.Deformat = function(blocks){
	if(!Array.isArray(blocks[0]))
		return blocks;
	var stream = [];
	for(var block = 0; block < blocks.length; block++)
		stream = stream.concat(blocks[block]);
	return stream;
};

MyCrypto.MCS.Paddings = {
	Nulls: {
		pad: function(bytes){
			while(bytes.length % 16 !== 0)
				bytes.push(0);
			return bytes;
		},
		unpad: function(bytes){
			while(bytes[bytes.length - 1] === 0)
				bytes.pop();
			return bytes;
		}
	},
	Insert: {
		pad: function(bytes){
			while(bytes.length % 16 !== 0)
				bytes.splice(Math.floor(Math.random() * (bytes.length + 1)), 0, 0);
			return bytes;
		},
		unpad: function(bytes){
			for(var byte = 0; byte < bytes.length; byte++){
				while(bytes[byte] === 0)
					bytes.splice(byte, 1);
			}
			return bytes;
		}
	},
	Pkcs7: {
		pad: function(bytes){
			var diff = (bytes.length % 16 - 16) * (-1);
			if(diff === 0)
				return bytes;
			var padd = [diff];
			while((bytes.length + padd.length) % 16 !== 0)
				padd.unshift(diff);
			padd = padd.slice(-diff);
			bytes = bytes.concat(padd);
			return bytes;
		},
		unpad: function(bytes){
			var info = bytes[bytes.length - 1];
			if(info > 16)
				return bytes;
			var testend = bytes.slice(-info);
			for(var tested = 0; tested < testend.length; tested++){
				if(testend[tested] != info)
					return bytes;
			}
			return bytes.slice(0, bytes.length - info);
		}
	},
	ISO_10126: {
		pad: function(bytes){
			var diff = (bytes.length % 16 - 16) * (-1);
			if(diff === 0){
				bytes.push(0);
				diff = (bytes.length % 16 - 16) * (-1) + 1;
			}
			var padd = [diff];
			while((bytes.length + padd.length) % 16 !== 0)
				padd.unshift(Math.floor(Math.random() * 256));
			padd = padd.slice(-diff);
			bytes = bytes.concat(padd);
			return bytes;
		},
		unpad: function(bytes){
			var info = bytes[bytes.length - 1];
			if(info > 16)
				return bytes;
			if(info === 16){
				bytes = bytes.slice(0, bytes.length - 16);
				return bytes;
			}
			while((bytes.length % 16 - 16) * (-1) != info)
				bytes.pop();
			return bytes;
		}
	}
};

MyCrypto.MCS.encrypt = function(inp, key, dosalt){
	return MyCrypto.MCS.Encryptor({
		mode: "CBC",
		rounds: 9,
		salt: typeof dosalt == "undefined" ? true : dosalt,
		key: key,
		iv: true,
		encoding: {
			input: "Utf8",
			output: "Base64"
		},
		padding: "Pkcs7"
	}).encrypt(inp).toString();
};

MyCrypto.MCS.decrypt = function(inp, key, dosalt){
	return MyCrypto.MCS.Encryptor({
		mode: "CBC",
		rounds: 9,
		salt: typeof dosalt == "undefined" ? true : dosalt,
		key: key,
		iv: true,
		encoding: {
			input: "Utf8",
			output: "Base64"
		},
		padding: "Pkcs7"
	}).decrypt(inp).toString();
};

MyCrypto.MCS.exportObj = function(bdata, enc, used, inc, crypt){
	return {
		encryptor: crypt,
		usedParams: used,
		include: !!inc,
		encoding: (typeof enc == "object" && typeof enc.stringify == "function") ? enc.stringify :
					typeof enc == "function" ? enc :
					(typeof enc == "string" && MyCrypto.Enc.hasOwnProperty(enc)) ? MyCrypto.Enc[enc].stringify : MyCrypto.Enc.Hex.stringify,
		data: MyCrypto.MCS.Deformat(bdata),
		toString: function(custom, saltin){
			saltin = typeof saltin == "boolean" ? saltin : this.include;
			var tostr = (!saltin || !this.usedParams.salt) ? this.data : MyCrypto.Enc.Latin1.parse("Salted" + this.usedParams.salt.length.toString(32)).concat(this.usedParams.salt).concat(this.data); 
			if(typeof custom == "object" && typeof custom.stringify == "function")
				return custom.stringify(tostr);
			if(typeof custom == "function")
				return custom(tostr);
			return !custom ? this.encoding(tostr) : MyCrypto.Enc[custom].stringify(tostr);
		}
	};
};

MyCrypto.MCS.importObj = function(str, encoding){
	if(!encoding)
		throw "Encoding required";
	if(typeof str == "object" && Array.isArray(str.data))
		return str;
	encoding = (typeof encoding == "string" && MyCrypto.Enc.hasOwnProperty(encoding)) ? MyCrypto.Enc[encoding].parse : typeof encoding == "function" ? encoding : encoding.parse;
	var parsed = encoding(str);
	if(MyCrypto.Enc.Latin1.stringify(parsed.slice(0, 6)) == "Salted"){
		var info = parseInt(MyCrypto.Enc.Latin1.stringify(parsed.slice(6, 7)), 32);
		var slt = parsed.slice(7, 7 + info);
		var bdata = parsed.slice(7 + info);
	}
	else{
		var slt = false;
		var bdata = parsed;
	}
	return {
		data: bdata,
		salt: slt
	};
};

MyCrypto.MCS.settingsObj_structure = `settingsObj structure: {
	mode: string("CTR" or "CBC" or "CFB" or "ECB"),
	rounds: (integer 1-32)->main_encryption_rounds_count,
	salt: array(2-16)->raw_bytes or true->8_random_bytes or false->no_salt or (integer 2-16)->[x]_random_bytes,
	key: array(16)->raw_bytes or string->derive or true->random or false->zero-filled,
	iv: array(16)->raw_bytes or string->derive or true->from_key or false->zero-filled,
	encoding: {
		input: "Utf8" or "Ascii" or "Hex" or "Bin" or "Base64" or "Latin1",
		output: "Base64" or "Hex" or "Bin" or "Latin1"
	},
	padding: "Pkcs7" or "Insert" or "Nulls" or "ISO_10126" or false->no_padding
}`;

MyCrypto.MCS.toSettings = function(emode, erounds, keysett, ivsett, saltsett, padd, inputenc, outputenc){
	return {
		mode: emode,
		rounds: erounds,
		key: keysett,
		iv: ivsett,
		salt: saltsett,
		encoding: {
			input: inputenc,
			output: outputenc
		},
		padding: padd
	};
};

MyCrypto.MCS.Encryptor = function(settingsObj){
	if(!settingsObj)
		throw "Settings-object required, see MyCrypto.MCS.settingsObj_structure for the right structure";
	return {
		settings: settingsObj,
		encrypt: function(data, customcounter){
			if(!data)
				throw "No data to encrypt";
			var input = Array.isArray(data) ? data : MyCrypto.Enc[this.settings.encoding.input].parse(data);
			var salt  = Array.isArray(this.settings.salt) ? this.settings.salt :
						typeof this.settings.salt == "number" ? MyCrypto.MCS.RandomBytes(this.settings.salt) :
						this.settings.salt == false ? false : MyCrypto.MCS.RandomBytes(8);
			var key   = Array.isArray(this.settings.key) ? this.settings.key :
						this.settings.key == false ? [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] :
						this.settings.key == true ? MyCrypto.MCS.RandomBytes(16) : MyCrypto.MCS.DeriveKey(this.settings.key, salt, 128, 16);
			var iv    = Array.isArray(this.settings.iv) ? this.settings.iv :
						this.settings.iv == false ? [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] :
						this.settings.iv == true ? MyCrypto.MCS.Core.EncryptRound(MyCrypto.MCS.Core.ExpandKey(key, 10), key) :
						MyCrypto.MCS.DeriveKey(this.settings.iv, salt, 64, 16);
			if(!!this.settings.padding)
				input = MyCrypto.MCS.Paddings[this.settings.padding].pad(input);
			var endata = MyCrypto.MCS.Modes[this.settings.mode.toUpperCase()].encrypt(input, key, iv, this.settings.rounds, customcounter);
			return MyCrypto.MCS.exportObj(endata, MyCrypto.Enc[this.settings.encoding.output], {mode: this.settings.mode.toUpperCase(), key: key, iv: iv, salt: salt, rounds: this.settings.rounds}, (typeof this.settings.salt == "boolean" || typeof this.settings.salt == "number"), this);
		},
		decrypt: function(data, customcounter){
			if(!data)
				throw "No data to decrypt";
			if(typeof data == "object" && data.hasOwnProperty("usedParams")){
				var input = data.data;
				var salt = data.usedParams.salt;
				var key = data.usedParams.key;
				var iv = data.usedParams.iv;
			}
			else{
				var parsed = MyCrypto.MCS.importObj(data, MyCrypto.Enc[this.settings.encoding.output]);
				var input = Array.isArray(data) ? data : parsed.data;
				var salt  = Array.isArray(parsed.salt) ? parsed.salt : Array.isArray(this.settings.salt) ? this.settings.salt : false;
				var key   = Array.isArray(this.settings.key) ? this.settings.key :
							this.settings.key == false ? [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] :
							MyCrypto.MCS.DeriveKey(this.settings.key, salt, 128, 16);
				var iv    = Array.isArray(this.settings.iv) ? this.settings.iv :
							this.settings.iv == false ? [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] :
							this.settings.iv == true ? MyCrypto.MCS.Core.EncryptRound(MyCrypto.MCS.Core.ExpandKey(key, 10), key) :
							MyCrypto.MCS.DeriveKey(this.settings.iv, salt, 64, 16);
			}
			var dedata = MyCrypto.MCS.Modes[this.settings.mode.toUpperCase()].decrypt(input, key, iv, this.settings.rounds, customcounter);
			if(!!this.settings.padding)
				dedata = MyCrypto.MCS.Paddings[this.settings.padding].unpad(dedata);
			return MyCrypto.MCS.exportObj(dedata, MyCrypto.Enc[this.settings.encoding.input], {mode: this.settings.mode.toUpperCase(), key: key, iv: iv, salt: salt, rounds: this.settings.rounds}, false, this);
		}
	};
};

MyCrypto.MCS.Modes.ECB = {
	encrypt: function(data, key, iv, rounds){
		var blocks = MyCrypto.MCS.Format(data, 16), schedule = MyCrypto.MCS.Schedule(key, rounds);
		for(var state = 0; state < blocks.length; state++)
			blocks[state] = MyCrypto.MCS.Core.AddKey(blocks[state], key);
		for(var rnd = 0; rnd < schedule.length; rnd++){
			for(var state = 0; state < blocks.length; state++)
				blocks[state] = MyCrypto.MCS.Core.EncryptRound(blocks[state], schedule[rnd]);
		}
		return MyCrypto.MCS.Deformat(blocks);
	},
	decrypt: function(data, key, iv, rounds){
		var blocks = MyCrypto.MCS.Format(data, 16), schedule = MyCrypto.MCS.Schedule(key, rounds).reverse();
		for(var rnd = 0; rnd < schedule.length; rnd++){
			for(var state = 0; state < blocks.length; state++)
				blocks[state] = MyCrypto.MCS.Core.DecryptRound(blocks[state], schedule[rnd]);
		}
		for(var state = 0; state < blocks.length; state++)
			blocks[state] = MyCrypto.MCS.Core.SubKey(blocks[state], key);
		return MyCrypto.MCS.Deformat(blocks);
	}
};

MyCrypto.MCS.Modes.CBC = {
	encrypt: function(data, key, iv, rounds){
		var blocks = MyCrypto.MCS.Format(data, 16), schedule = MyCrypto.MCS.Schedule(key, rounds);
		var toxor = [iv];
		for(var state = 0; state < blocks.length; state++)
			blocks[state] = MyCrypto.MCS.Core.AddKey(blocks[state], key);
		for(var state = 0; state < blocks.length; state++){
			blocks[state] = MyCrypto.MCS.Core.ApplyKey(blocks[state], toxor[state]);
			for(var rnd = 0; rnd < schedule.length; rnd++)
				blocks[state] = MyCrypto.MCS.Core.EncryptRound(blocks[state], schedule[rnd]);
			toxor[state + 1] = blocks[state];
		}
		return MyCrypto.MCS.Deformat(blocks);
	},
	decrypt: function(data, key, iv, rounds){
		var blocks = MyCrypto.MCS.Format(data, 16), schedule = MyCrypto.MCS.Schedule(key, rounds).reverse();
		var toxor = [iv];
		for(var state = 0; state < blocks.length; state++)
			toxor[state + 1] = blocks[state].slice(0);
		for(var state = 0; state < blocks.length; state++){
			for(var rnd = 0; rnd < schedule.length; rnd++)
				blocks[state] = MyCrypto.MCS.Core.DecryptRound(blocks[state], schedule[rnd]);
			blocks[state] = MyCrypto.MCS.Core.ApplyKey(blocks[state], toxor[state]);
		}
		for(var state = 0; state < blocks.length; state++)
			blocks[state] = MyCrypto.MCS.Core.SubKey(blocks[state], key);
		return MyCrypto.MCS.Deformat(blocks);
	}
};

MyCrypto.MCS.Modes.CFB = {
	encrypt: function(data, key, iv, rounds){
		var blocks = MyCrypto.MCS.Format(data, 16), schedule = MyCrypto.MCS.Schedule(key, rounds);
		var init = [iv];
		for(var state = 0; state < blocks.length; state++)
			blocks[state] = MyCrypto.MCS.Core.AddKey(blocks[state], key);
		for(var state = 0; state < blocks.length; state++){
			for(var rnd = 0; rnd < schedule.length; rnd++)
				init[state] = MyCrypto.MCS.Core.EncryptRound(init[state], schedule[rnd]);
			blocks[state] = MyCrypto.MCS.Core.ApplyKey(blocks[state], init[state]);
			init[state + 1] = blocks[state];
		}
		return MyCrypto.MCS.Deformat(blocks);
	},
	decrypt: function(data, key, iv, rounds){
		var blocks = MyCrypto.MCS.Format(data, 16), schedule = MyCrypto.MCS.Schedule(key, rounds);
		var init = [iv];
		for(var state = 0; state < blocks.length; state++)
			init[state + 1] = blocks[state].slice(0);
		for(var state = 0; state < blocks.length; state++){
			for(var rnd = 0; rnd < schedule.length; rnd++)
				init[state] = MyCrypto.MCS.Core.EncryptRound(init[state], schedule[rnd]);
			blocks[state] = MyCrypto.MCS.Core.ApplyKey(blocks[state], init[state]);
		}
		for(var state = 0; state < blocks.length; state++)
			blocks[state] = MyCrypto.MCS.Core.SubKey(blocks[state], key);
		return MyCrypto.MCS.Deformat(blocks);
	}
};

MyCrypto.MCS.Modes.CTR = {
	encrypt: function(data, key, iv, rounds, cnt, inverse){
		var blocks = MyCrypto.MCS.Format(data, 16), schedule = MyCrypto.MCS.Schedule(key, rounds);
		var increment = function(cnt){
			var newc = cnt.slice(0).reverse();
			for(var i = 0; i < newc.length; i++){
				if(newc[i] >= 255)
					newc[i] = 0;
				else{
					newc[i]++;
					break;
				}
			}
			return newc.reverse();
		};
		var init = [];
		var counter = typeof cnt == "number" ? [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, cnt >>> 24, cnt << 8 >>> 24, cnt << 16 >>> 24, cnt << 24 >>> 24] :
						Array.isArray(cnt) ? [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].concat(cnt).slice(-16) : [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
		if(!inverse){
			for(var state = 0; state < blocks.length; state++)
				blocks[state] = MyCrypto.MCS.Core.AddKey(blocks[state], key);
		}
		for(var state = 0; state < blocks.length; state++){
			init[state] = MyCrypto.MCS.Core.ApplyKey(counter, iv);
			for(var rnd = 0; rnd < schedule.length; rnd++)
				init[state] = MyCrypto.MCS.Core.EncryptRound(init[state], schedule[rnd]);
			blocks[state] = MyCrypto.MCS.Core.ApplyKey(blocks[state], init[state]);
			counter = increment(counter);
		}
		if(!!inverse){
			for(var state = 0; state < blocks.length; state++)
				blocks[state] = MyCrypto.MCS.Core.SubKey(blocks[state], key);
		}
		return MyCrypto.MCS.Deformat(blocks);
	},
	decrypt: function(data, key, iv, rounds, cnt){
		return MyCrypto.MCS.Modes.CTR.encrypt(data, key, iv, rounds, cnt, true);
	}
};



MyCrypto.CRC.table = [0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
						0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
						0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
						0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
						0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
						0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
						0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
						0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
						0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
						0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
						0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
						0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
						0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
						0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
						0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
						0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
						0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
						0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
						0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
						0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
						0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
						0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
						0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
						0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
						0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
						0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
						0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
						0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
						0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
						0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
						0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
						0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d];

MyCrypto.CRC.Digest = function(string){
	var crc = -1;
	for(var i = 0, iTop = string.length; i < iTop; i++)
		crc = (crc >>> 8) ^ MyCrypto.CRC.table[(crc ^ string.charCodeAt(i)) & 0xFF];
	return {
		words: [(crc ^ -1) >>> 0],
		toString: function(custom){
			if(typeof custom == "string" && MyCrypto.Enc.hasOwnProperty(custom))
				return MyCrypto.Enc[custom].stringify(this.toBytes());
			else if(typeof custom == "object" && custom.hasOwnProperty("stringify"))
				return custom.stringify(this.toBytes());
			else if(typeof custom == "number"){
				custom = (custom >= 2 && custom < 37) ? custom : 16;
				var lng = (Math.pow(2, 32) - 1).toString(custom).length;
				var str = "";
				for(var ix = 0; ix < this.words.length; ix++)
					str += ("00000000000000000000000000000000" + this.words[ix].toString(custom)).substr(-lng);
				return str;
			}
			else
				return MyCrypto.Enc.Hex.stringify(this.toBytes());
		},
		toBytes: function(){
			return MyCrypto.Enc.Words.from(this.words);
		}
	};
};

MyCrypto.CRC.Extended = function(string, wordscount, countsensitive){
	var wrdcnt = (typeof wordscount == "number"&& wordscount > 0) ? wordscount > 4096 ? 4096 : wordscount : 1;
	var wrds = [];
	var str = string + ((typeof countsensitive == "undefined" || countsensitive == true) ? wordscount.toString(32) : "");
	var hsh, bts;
	for(var rnd = 0; rnd <= wrdcnt; rnd++){
		hsh = MyCrypto.CRC.Digest(rnd % 2 == 0 ? str + string : str + string.split("").reverse().join("")).words;
		wrds.push(hsh[0]);
		str += MyCrypto.Enc.Latin1.stringify(MyCrypto.Enc.Words.from(hsh));
	}
	wrds.shift();
	return {
		words: wrds,
		toString: function(custom){
			if(typeof custom == "string" && MyCrypto.Enc.hasOwnProperty(custom))
				return MyCrypto.Enc[custom].stringify(this.toBytes());
			else if(typeof custom == "object" && custom.hasOwnProperty("stringify"))
				return custom.stringify(this.toBytes());
			else if(typeof custom == "number"){
				custom = (typeof custom == "number" && custom >= 2 && custom < 37) ? custom : 16;
				var lng = (Math.pow(2, 32) - 1).toString(custom).length;
				var str = "";
				for(var ix = 0; ix < this.words.length; ix++)
					str += ("00000000000000000000000000000000" + this.words[ix].toString(custom)).substr(-lng);
				return str;
			}
			else
				return MyCrypto.Enc.Hex.stringify(this.toBytes());
		},
		toBytes: function(){
			return MyCrypto.Enc.Words.from(this.words);
		}
	};
};
