import hashlib
import hmac
import codecs
def toUTF16LE(msg):   
    byteArray = bytearray(len(msg) * 2);
    for i in range(len(msg)):
        byteArray[i * 2] = ord(msg[i]) & 0xff
        byteArray[i * 2 + 1] = ord(msg[i]) >> 8 & 0xff
    return byteArray
def ntlm(msg):
    hash = hashlib.new('md4')
    hash.update(toUTF16LE(msg))
    return hash.hexdigest()
def hmac_md5(password, msg):
    return hmac.new(password, msg, hashlib.md5).hexdigest()
def ntlmv2(password, user, domain):
    return hmac_md5(codecs.decode(ntlm(password), "hex"), toUTF16LE(user.upper() + domain))
def netntlmv2(password, user, domain, proofStr, blob):
    ntlmv2_buffer = codecs.decode(ntlmv2(password, user, domain), 'hex')
    blockToHmac = codecs.decode(proofStr + blob, 'hex')
    hashedBlock = hmac_md5(ntlmv2_buffer, blockToHmac)
    return hashedBlock
def isEmptyPassword(formattedHash):
    passwordToTry = ""
    splitted = formattedHash.split(":")  
    if len(splitted) < 6: 
        return False     
    user = splitted[0]
    domain = splitted[2]
    challenge = splitted[3]
    targetHash = splitted[4]
    blob = splitted[5]
    if len(targetHash) == 32:
        generatedHash = netntlmv2(passwordToTry, user, domain, challenge, blob)
    return generatedHash.upper() == targetHash.upper()
with open("hashes.txt", "r") as currentData:
    if isEmptyPassword(currentData.read().splitlines()[0]):
        print("password is correct!")
