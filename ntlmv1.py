import hashlib
from Crypto.Cipher.DES import new,MODE_ECB
"""
hashcat/blob/master/src/modules/module_05500.c
static void transform_netntlmv1_key (const u8 *nthash, u8 *key)
{
  key[0] =                    (nthash[0] >> 0);
  key[1] = (nthash[0] << 7) | (nthash[1] >> 1);
  key[2] = (nthash[1] << 6) | (nthash[2] >> 2);
  key[3] = (nthash[2] << 5) | (nthash[3] >> 3);
  key[4] = (nthash[3] << 4) | (nthash[4] >> 4);
  key[5] = (nthash[4] << 3) | (nthash[5] >> 5);
  key[6] = (nthash[5] << 2) | (nthash[6] >> 6);
  key[7] = (nthash[6] << 1);

  key[0] |= 0x01;
  key[1] |= 0x01;
  key[2] |= 0x01;
  key[3] |= 0x01;
  key[4] |= 0x01;
  key[5] |= 0x01;
  key[6] |= 0x01;
  key[7] |= 0x01;
}
"""
"""
Java
private static Key createDESKey(byte[] bytes, int offset) {
        byte[] keyBytes = new byte[7];
        System.arraycopy(bytes, offset, keyBytes, 0, 7);
        byte[] material = new byte[8];
        material[0] = keyBytes[0];
        material[1] = (byte) (keyBytes[0] << 7 | (keyBytes[1] & 0xff) >>> 1);
        material[2] = (byte) (keyBytes[1] << 6 | (keyBytes[2] & 0xff) >>> 2);
        material[3] = (byte) (keyBytes[2] << 5 | (keyBytes[3] & 0xff) >>> 3);
        material[4] = (byte) (keyBytes[3] << 4 | (keyBytes[4] & 0xff) >>> 4);
        material[5] = (byte) (keyBytes[4] << 3 | (keyBytes[5] & 0xff) >>> 5);
        material[6] = (byte) (keyBytes[5] << 2 | (keyBytes[6] & 0xff) >>> 6);
        material[7] = (byte) (keyBytes[6] << 1);
        oddParity(material);
        return new SecretKeySpec(material, "DES");
    }
"""

def transform_netntlmv1_key(nthash,key):
    nthash = [l & 0xff for l in nthash]    
    key[0] =                     (nthash[0] >> 0)
    key[1] = ((nthash[0] << 7) | (nthash[1] >> 1)) & 0xff 
    key[2] = ((nthash[1] << 6) | (nthash[2] >> 2)) & 0xff 
    key[3] = ((nthash[2] << 5) | (nthash[3] >> 3)) & 0xff 
    key[4] = ((nthash[3] << 4) | (nthash[4] >> 4)) & 0xff 
    key[5] = ((nthash[4] << 3) | (nthash[5] >> 5)) & 0xff 
    key[6] = ((nthash[5] << 2) | (nthash[6] >> 6)) & 0xff    
    key[7] = (nthash[6] << 1)  
    key[0] |= 0x01  
    key[1] |= 0x01
    key[2] |= 0x01 
    key[3] |= 0x01 
    key[4] |= 0x01  
    key[5] |= 0x01 
    key[6] |= 0x01  
    key[7] |= 0x01 
    return key

"""
Java
public static byte[] getNTLM2SessionResponse(String password,
            byte[] challenge, byte[] clientNonce) throws Exception {
        byte[] ntlmHash = ntlmHash(password);
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update(challenge);
        md5.update(clientNonce);
        byte[] sessionHash = new byte[8];
        System.arraycopy(md5.digest(), 0, sessionHash, 0, 8);
        return lmResponse(ntlmHash, sessionHash);
    }
private static byte[] lmResponse(byte[] hash, byte[] challenge)
            throws Exception {
        byte[] keyBytes = new byte[21];
        System.arraycopy(hash, 0, keyBytes, 0, 16);
        Key lowKey = createDESKey(keyBytes, 0);
        Key middleKey = createDESKey(keyBytes, 7);
        Key highKey = createDESKey(keyBytes, 14);
        Cipher des = Cipher.getInstance("DES/ECB/NoPadding");
        des.init(Cipher.ENCRYPT_MODE, lowKey);
        byte[] lowResponse = des.doFinal(challenge);
        des.init(Cipher.ENCRYPT_MODE, middleKey);
        byte[] middleResponse = des.doFinal(challenge);
        des.init(Cipher.ENCRYPT_MODE, highKey);
        byte[] highResponse = des.doFinal(challenge);
        byte[] lmResponse = new byte[24];
        System.arraycopy(lowResponse, 0, lmResponse, 0, 8);
        System.arraycopy(middleResponse, 0, lmResponse, 8, 8);
        System.arraycopy(highResponse, 0, lmResponse, 16, 8);
        return lmResponse;
    }
"""
def netntlmv1_empty_checker(netntlm_t, password):
    hc_token_t = netntlm_t.split(':')    
    lmResponse = bytes.fromhex(hc_token_t[3])
    ntresponse = bytes.fromhex(hc_token_t[4])
    challenge = bytes.fromhex(hc_token_t[5])
    clientNonce = lmResponse[0:8]
    """
    the 8 byte server challenge is concatednated 
    with the 8 byte client challenge,yielding the "session nonce"
    """  
    sessionHash = hashlib.md5(challenge)
    sessionHash.update(clientNonce)
    sessionHash = sessionHash.digest()[:8]
    """
    the session nonce is MD5 hashed,yielding a 16 byte hash 
    the 16 byte hash is truncated to 8 bytes,yielding the NTLMv1 ESS hash.    
    """
    hash = hashlib.new('md4', password.encode('utf-16le')).digest()
    """
    the 16 byte NT hash(AKA MD4 hash of user password) is null-padded to 21 bytes.
    """
    keyBytes = hash.ljust(21, b'\x00')
    """
    The 16-byte NTLM hash is null-padded to 21 bytes.
    """
    lowKey = keyBytes[0:7]
    middleKey = keyBytes[7:14]
    highKey = keyBytes[14:21]
    """
    The value is split into three 7-byte thrids
    """
    lowResponse = transform_netntlmv1_key(lowKey,bytearray(8))
    middleResponse = transform_netntlmv1_key(middleKey,bytearray(8))
    highResponse = transform_netntlmv1_key(highKey,bytearray(8))
    """
    These values are used to create three DES keys
    (one from each 7-byte third)
    """    
    return new(lowResponse, MODE_ECB).encrypt(sessionHash)+new(middleResponse, MODE_ECB).encrypt(sessionHash)+new(highResponse, MODE_ECB).encrypt(sessionHash)==ntresponse
    """
    each third is used as a DES key to encrypt the NTLMv1 ESS hash,resulting in three 8 byte ciphertext values.
    These three 8 byte ciphertext values are concatednated,resulting in the 24 byte NTLMv1 ESS Response.
    """
if __name__ == "__main__":
    RawHash = "lyc::SXSYMXSYY-PC:4bf50c3614e7257600000000000000000000000000000000:59e47b73556d0dbfdb2705eb111eb1e0af0ecfc8a0281d63:bd756289919e57e6"
    lyc = "lyc"
    print(netntlmv1_empty_checker(RawHash, lyc))