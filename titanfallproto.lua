your_proto = Proto("titanfallproto", "Titanfall Protocol Decryptor by p0358")
your_proto.prefs.key = Pref.string("Decryption key (base64)", "", "128-bit AES key (in base64)")

require('base64')
local gcrypt = require("luagcrypt")

local ef_gamedata     = ProtoExpert.new("titanfallproto.gamedata.expert", "Game data",
                                     expert.group.REQUEST_CODE, expert.severity.CHAT)
local ef_query     = ProtoExpert.new("titanfallproto.query.expert", "DNS query message",
                                     expert.group.REQUEST_CODE, expert.severity.CHAT)
local ef_response  = ProtoExpert.new("titanfallproto.response.expert", "DNS response message",
                                     expert.group.RESPONSE_CODE, expert.severity.CHAT)
local ef_ultimate  = ProtoExpert.new("titanfallproto.response.ultimate.expert", "DNS answer to life, the universe, and everything",
                                     expert.group.COMMENTS_GROUP, expert.severity.NOTE)
-- some error expert info's
local ef_too_short = ProtoExpert.new("titanfallproto.too_short.expert", "packet too short",
                                     expert.group.MALFORMED, expert.severity.ERROR)
local ef_no_decryption_key = ProtoExpert.new("titanfallproto.no_decryption_key.expert", "no decryption key provided - cannot decrypt (check protocol settings)",
                                     expert.group.MALFORMED, expert.severity.ERROR)
local ef_bad_query = ProtoExpert.new("titanfallproto.query.missing.expert", "DNS query missing or malformed",
                                     expert.group.MALFORMED, expert.severity.WARN)
 -- register them
your_proto.experts = { ef_gamedata, ef_query, ef_too_short, ef_no_decryption_key, ef_bad_query, ef_response, ef_ultimate }


local pf_nonce              = ProtoField.new   ("Nonce", "titanfallproto.nonce", ftypes.BYTES, nil, base.SPACE) -- DOT, DASH, COLON or SPACE
local pf_tag              = ProtoField.new   ("Tag", "titanfallproto.tag", ftypes.BYTES, nil, base.SPACE) -- DOT, DASH, COLON or SPACE
local pf_raw              = ProtoField.new   ("Raw encrypted data", "titanfallproto.raw", ftypes.BYTES, nil, base.SPACE) -- DOT, DASH, COLON or SPACE
local pf_key_base64              = ProtoField.new   ("Current key", "titanfallproto.key_base64", ftypes.STRING, nil, base.UNICODE) -- ASCII or UNICODE
local pf_decrypted              = ProtoField.new   ("Decrypted data", "titanfallproto.decrypted", ftypes.BYTES, nil, base.SPACE) -- DOT, DASH, COLON or SPACE
local pf_decrypted_string              = ProtoField.new   ("Decrypted data string", "titanfallproto.decrypted_string", ftypes.STRING, nil, base.ASCII) -- DOT, DASH, COLON or SPACE
local pf_decrypted_sha256              = ProtoField.new   ("Decrypted data sha256 checksum", "titanfallproto.decrypted_sha256", ftypes.STRING, nil, base.ASCII) -- DOT, DASH, COLON or SPACE
--add_field(ProtoField.bytes, "data_dec", "Decrypted data")
local pf_data_dec = ProtoField.bytes("titanfallproto.data_dec", "data_dec", "Decrypted data")
local pf_data = ProtoField.bytes("titanfallproto.data", "data", "Packet data")

your_proto.fields = { pf_nonce, pf_tag, pf_raw, pf_key_base64, pf_decrypted, pf_decrypted_string, pf_decrypted_sha256, pf_data_dec, pf_data }


function decrypt_(key, data)
    local iv = string.sub(data, -16)
    local ciphertext = string.sub(data, 1, -17)
    local cipher = gcrypt.Cipher(gcrypt.CIPHER_AES256, gcrypt.CIPHER_MODE_CBC)
    cipher:setkey(key)
    cipher:setiv(iv)
    return cipher:decrypt(ciphertext)
end

function decrypt(key, nonce, tag, ciphertext)
    local cipher = gcrypt.Cipher(gcrypt.CIPHER_AES128, gcrypt.CIPHER_MODE_GCM)
    cipher:setkey(key)
    cipher:setiv(nonce)
    return cipher:decrypt(ciphertext)
end

function sha256(data)
    -- http://csrc.nist.gov/groups/ST/toolkit/examples.html
    local md = gcrypt.Hash(gcrypt.MD_SHA256)
    md:write(data)
    return Struct.tohex(md:read(gcrypt.MD_SHA256))
end


function test_aes_gcm_128()
    --if not check_version("1.6.0") then return end
    -- http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
    -- Test case 4
    local plaintext_spec = fromhex("d9313225f88406e5a55909c5aff5269a" ..
                                   "86a7a9531534f7da2e4c303d8a318a72" ..
                                   "1c3c0c95956809532fcf0e2449a6b525" ..
                                   "b16aedf5aa0de657ba637b39")
    local ciphertext_spec = fromhex("42831ec2217774244b7221b784d0d49c" ..
                                    "e3aa212f2c02a4e035c17e2329aca12e" ..
                                    "21d514b25466931c7d8f6a5aac84aa05" ..
                                    "1ba30b396a0aac973d58e091")
    local adata = fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    local atag = fromhex("5bc94fbc3221a5db94fae95ae7121a47")
    local iv = fromhex("cafebabefacedbaddecaf888")
    local cipher = gcrypt.Cipher(gcrypt.CIPHER_AES128, gcrypt.CIPHER_MODE_GCM)
    cipher:setkey(fromhex("feffe9928665731c6d6a8f9467308308"))
    cipher:setiv(iv)
    cipher:authenticate(adata)
    assert(cipher:encrypt(plaintext_spec) == ciphertext_spec)
    assert(cipher:gettag() == atag)
    cipher:checktag(atag)

    cipher:reset()
    cipher:setiv(iv)
    assert(cipher:decrypt(ciphertext_spec) == plaintext_spec)
end

--function your_proto.dissector(tvb, pinfo, tree)
function your_proto.dissector(tvbuf, pktinfo, root)
    pktinfo.cols.protocol:set("Titanfall")
    
    local pktlen = tvbuf:reported_length_remaining()
    local tree = root:add(your_proto, tvbuf:range(0,pktlen))
    
    
    if pktlen <= 28 then
        -- since we're going to add this protocol to a specific UDP port, we're going to
        -- assume packets in this port are our protocol, so the packet being too short is an error
        tree:add_proto_expert_info(ef_too_short)
        --dprint("packet length",pktlen,"too short")
        return
    end
    
    tree:add(pf_nonce, tvbuf:range(0,12))
    tree:add(pf_tag, tvbuf:range(12,16))
    local subtree = tree:add(pf_raw, tvbuf:range(28,pktlen-28))
        
    local decryption_key_base64 = your_proto.prefs.key
    if decryption_key_base64 == nil or decryption_key_base64 == '' then
        tree:add_proto_expert_info(ef_no_decryption_key)
        return
    end
    local decryption_key = from_base64(decryption_key_base64)
    
    tree:add(pf_key_base64, decryption_key_base64)
    
    --local subtree = tree:add(pf_data, tvbuf:range(28,pktlen-28))
    
    if decryption_key then
        local enc_data = tvbuf:raw(28)
        local decrypted_bytes = decrypt(decryption_key, tvbuf:raw(0,12), tvbuf:raw(12,16), enc_data)
        --tree:add(pf_decrypted, Struct.tohex(decrypted_bytes))
        
        local dec_data = ByteArray.new(decrypted_bytes, true)
            :tvb("Decrypted data")
        --if pkt_type == 0x01 and dec_data(7, 1):uint() == 0x86 then
        --    local key = data_key(decryption_key, decrypted_bytes)
        --    kdnet_stored_key(pinfo, key)
        --end
        --local subtree_dec = subtree:add(pf_data_dec, dec_data())
        local subtree_dec = subtree:add(pf_decrypted, dec_data())
        --dissect_kdnet_data(dec_data, pinfo, pkt_type, subtree_dec)
        subtree:add(pf_decrypted_string, decrypted_bytes)
        subtree:add(pf_decrypted_sha256, sha256(decrypted_bytes))
    end
    
    
    --decrypt(tvb, tvb())  -- assume suitable "decrypt" routine
    --decrypt(tvb, tvb())  -- assume suitable "decrypt" routine
end

DissectorTable.get("udp.port"):add(30000, your_proto)
DissectorTable.get("udp.port"):add(27005, your_proto)
DissectorTable.get("udp.port"):add(27015, your_proto)
DissectorTable.get("udp.port"):add(37005, your_proto)
DissectorTable.get("udp.port"):add(37015, your_proto)

--dprint2("penis")
