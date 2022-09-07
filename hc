const fs = require("fs")
const colors = require("colors")

String.prototype.fromBase64 = function(charsetString, paddingString) {
    if (!charsetString) {
    	charsetString = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    }
    
    if (!paddingString) {
    	paddingString = "=";
    }
    
    const base64chars = charsetString;
    let result = '', encoded = '';
    
    const base64inv = {};
    
    for (let i = 0; i < base64chars.length; i++)
      base64inv[base64chars[i]] = i;
  
    const base64regex = new RegExp(`[^${base64chars}=]`, 'g');
    encoded = this.replace(base64regex, '');
  
    const onePadding = encoded.charAt(encoded.length - 1) === paddingString;
    const twoPadding = encoded.charAt(encoded.length - 2) === paddingString;  
    const padding = onePadding ? twoPadding ? 'AA' : 'A' : '';
    encoded = encoded.substring(0, encoded.length - padding.length) + padding;
  
    for (let i = 0; i < encoded.length; i += 4) {
    	const dn = base64inv[encoded.charAt(i)];
        const en = base64inv[encoded.charAt(i + 1)];
        const fn = base64inv[encoded.charAt(i + 2)];
        const gn = base64inv[encoded.charAt(i + 3)];
        const d = dn << 18;
        const e = en << 12;
        const f = fn << 6;
        const g = gn;
        const n = d + e + f + g;        
        const a = (n >>> 16) & 255;
        const b = (n >>> 8) & 255;
        const c = n & 255;     
        result += String.fromCharCode(a, b, c);
    }
    return result.substring(0, result.length - padding.length);
}

function reverseString(string) {
    let newString = "";
    let stringLength = string.length - 1;
    while(stringLength != -1) {
        newString += string[stringLength];
        stringLength--;
    }
    return newString;
}

function xorCrypto(key, data) {
    let preData, result;
    preData = "";
    result = "";
    for (let c = 0; c < data.length;) {
        if (c >= data.length) {
        	break;
        }
        preData += String.fromCharCode(parseInt(data.substring(c, c + 2), 16));
        c = c + 2;
    }
    for (let a = 0, b = 0; a < preData.length; a++, b++) {
        if (b >= key.length) {
        	b = 0
        }
        result += String.fromCharCode(preData.charCodeAt(a) ^ key.charCodeAt(b));
    }
    return result;
}

const decrypthc = (configSalt, value) => {
	const text = reverseString(value).fromBase64("RkLC2QaVMPYgGJW/A4f7qzDb9e+t6Hr0Zp8OlNyjuxKcTw1o5EIimhBn3UvdSFXs?", "?")
	return xorCrypto(configSalt, text)
}

const decrypthcl = (configSalt, value) => {
	const text = reverseString(value).fromBase64("t6uxKcTwhBn3UvRkLC2QaVM1o5A4f7Hr0Zp8OyjqzDb9e+dSFXsEIimPYgGJW/lN?", "?")
	return xorCrypto(configSalt, text)
}

class HttpInjector {
	constructor(hc) {
		this.hc = hc
		this.salt = hc.configSalt
		this.tunnelMode = hc.tunnelType
	}
	decrypt(key) {
		if (this.hc.configVersionCode > 10000) {
			return (this.hc[key]) ? decrypthcl(this.salt, this.hc[key]) : 'N/A'
		} else {
			return (this.hc[key]) ? decrypthc(this.salt, this.hc[key]) : 'N/A'
		}
	}
	tunnelType() {
		switch (this.tunnelMode) {
			case "ssl_proxy_payload_ssh":
			    return "SSH -> TLS/SSL + Proxy -> Custom Payload"
			case "http_obfs_shadowsocks":
			    return "Shadowsocks -> HTTP (Obfs)"
			case "ssl_ssh":
			    return "SSH -> TLS/SSL (stunnel)"
			case "proxy_payload_ssh":
			    return "SSH -> HTTP Proxy -> Custom Payload"
			case "proxy_ssh":
			    return "SSH -> HTTP Proxy"
			case "direct_payload_ssh":
			    return "SSH -> Direct -> Custom Payload"
			default:
			    return this.tunnelMode
		}
	}
}

const parseConfig = (hc, personalizado = true) => {
	
	if (!hc.configSalt) hc.configSalt = "EVZJNI"
	
	const httpInjector = new HttpInjector(hc)
	
	var message = ""

	if (personalizado) {
		
		if (hc.tunnelType == "http_obfs_shadowsocks") {
			
			const settings = JSON.parse(httpInjector.decrypt("httpObfsSettings"))
			
			message += `Shadowsocks:\n`
			message += `Host: ${httpInjector.decrypt("shadowsocksHost")}\n`
			message += `Puerto:a ${hc.shadowsocksPort}\n`
			message += `Contra: ${httpInjector.decrypt("shadowsocksPassword")}\n`
			message += `EncryptMethod: ${hc.shadowsocksEncryptionMethod.toUpperCase()}\n\n`
			message += `Settings:\n`
			message += `Method: ${settings.httpMethod}\n`
			message += `Hostname: ${settings.hostname}\n\n`
			
			message += `Tipo de túnel: ${httpInjector.tunnelType()}\n\n`
			
		} else if (hc.tunnelType == "direct_v2r_vmess") {
			
			message += `V2Ray Settings:\n`
			message += `Protocol: ${httpInjector.decrypt("v2rProtocol")}\n`
			message += `Host: ${httpInjector.decrypt("v2rHost")}\n`
			message += `Porta: ${httpInjector.decrypt("v2rPort")}\n`
			message += `User ID: ${httpInjector.decrypt("v2rUserId")}\n`
			message += `Alter ID: ${httpInjector.decrypt("v2rAlterId")}\n`
			message += `Security: ${httpInjector.decrypt("v2rVlessSecurity")}\n`
			
			if (hc.v2rNetwork) message += `Network Type: ${httpInjector.decrypt("v2rNetwork")}\n`
			if (hc.v2rWsHeader) message += `Header: ${httpInjector.decrypt("v2rWsHeader")}\n`
			if (hc.v2rWsPath) message += `Header Path: ${httpInjector.decrypt("v2rWsPath")}\n`
			if (hc.v2rTlsSni) message += `TLS SNI: ${httpInjector.decrypt("v2rTlsSni")}\n`
			
			if (hc.v2rRawJson) {
				message = httpInjector.decrypt("v2rRawJson")
			}
			
		} else if (["ssl_proxy_payload_ssh","ssl_ssh","proxy_payload_ssh","direct_payload_ssh","proxy_ssh"].includes(hc.tunnelType)) {
			
			message += `SSH:\n`
			
			if (hc.overwriteServerData) {
				var serverData = JSON.parse(hc.overwriteServerData)
				message += `Servidor da Evozi: ${serverData.name} (${serverData.ip})\n`
				message += `Puertos: ${serverData.sshPort} SSH, ${serverData.sshSslPort} SSL\n\n`
				// message += `User: ${serverData.sshUsername}\n`
				// message += `Password: ${serverData.sshPassword}\n\n`
			} else {
				message += `Host: ${httpInjector.decrypt("host")}\n`
				message += `Porta: ${hc.port}\n`
				message += `Usuario: ${httpInjector.decrypt("user")}\n`
				message += `Contra: ${httpInjector.decrypt("password")}\n\n`
			}
			
			if (hc.configHwid) {
				message += `HWID: ${hc.configHwid}\n`
			}
			
			if (hc.payload) {
				message += `Payload: ${httpInjector.decrypt("payload")}\n\n`
			}
			
			if (hc.remoteProxy) {
				if (hc.remoteProxyUsername) {
					message += `Proxy: ${httpInjector.decrypt("remoteProxy")}\n`
					message += `Proxy Auth: ${httpInjector.decrypt("remoteProxyUsername")} : ${httpInjector.decrypt("remoteProxyPassword")}\n`
				} else {
					message += `Proxy: ${httpInjector.decrypt("remoteProxy")}\n\n`
				}
				
			} else if (hc.overwriteServerData) {
				message += `Proxy: ${serverData.proxyIp}\n`
				message += `ProxyPort: ${serverData.proxyPort}\n\n`
			}
			
			if (hc.sniHostname != "N/A" && hc.tunnelType != "proxy_payload_ssh") {
				message += `SNI: ${httpInjector.decrypt("sniHostname")}\n\n`
			}
			
			message += `Tipo de túnel: ${httpInjector.tunnelType()}\n\n`
			
		}
		
		//delete hc.configSalt
		delete hc.configMessage
		
		console.log(message)
		
		fs.writeFileSync("/sdcard/hc.txt", message)
		fs.writeFileSync("/sdcard/decrypt.txt", JSON.stringify(hc, null, 4))
	
		return hc
		
	} else {
		return console.log(hc)
	}
	
	return hc
}

console.clear()

const decryptFile = fs.readFileSync("/sdcard/decrypt.txt", "utf-8")

try {
	var file = JSON.parse(decryptFile)
} catch (err) {
	var file = JSON.parse(decryptFile.split('}')[0] + '}')
}

console.log(colors.brightGreen("\nArchivo abierto por @JuanFCol"))

parseConfig(file, 1)
