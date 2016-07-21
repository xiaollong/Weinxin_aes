class Weixin_aes

  BLOCK_SIZE = 32

  # 对需要加密的明文进行填充补位
  # 返回补齐明文字符串
  def pkcs7encode(text)
    # 计算需要填充的位数
    amount_to_pad = BLOCK_SIZE - (text.length % BLOCK_SIZE)
    amount_to_pad = BLOCK_SIZE if amount_to_pad == 0
    # 获得补位所用的字符
    pad_chr = amount_to_pad.chr
    "#{text}#{pad_chr * amount_to_pad}"
  end

  # 对解密结果删除补位
  def pkcs7decode(text)
    pad = text[-1].ord
    pad = 0 if (pad < 1 || pad > BLOCK_SIZE)
    size = text.size - pad
    text[0...size]
  end

  #加密
  def encrypt(aes_key, text, corpid)
    text    = text.force_encoding("ASCII-8BIT")
    random  = SecureRandom.hex(8)
    msg_len = [text.length].pack("N")
    text    = "#{random}#{msg_len}#{text}#{corpid}"
    text    = pkcs7encode(text)
    text    = handle_cipher(:encrypt, aes_key, text)
    Base64.strict_encode64(text)
  end

  # 解密.
  # text 需要解密的密文
  def decrypt(aes_key, text, corpid)
    text        = Base64.decode64(text)
    text        = handle_cipher(:decrypt, aes_key, text)
    result      = pkcs7decode(text)
    content     = result[16...result.length]
    len_list    = content[0...4].unpack("N")
    xml_len     = len_list[0]
    xml_content = content[4...4 + xml_len]
    from_corpid = content[xml_len+4...content.size]
    # TODO: refactor
    if corpid != from_corpid
      Rails.logger.debug("#{__FILE__}:#{__LINE__} Failure because #{corpid} != #{from_corpid}")
      status = 401
    end
    #[xml_content, status]
    xml_content
  end

  #aes加密
  def handle_cipher(action, aes_key, text)
    cipher = OpenSSL::Cipher.new('AES-256-CBC')
    cipher.send(action)
    cipher.padding = 0
    aes_key        = Base64.decode64(aes_key + "=")
    cipher.key     = aes_key
    cipher.iv      = aes_key[0...16]
    cipher.update(text) + cipher.final
  end

  #验证是否为微信过来的请求,公众号服务器验证用
  def verify_wx_url(signature,wx_token, timestamp, nonce)
    array = [wx_token, timestamp, nonce].sort
    result= 0
    result= 1 if signature == Digest::SHA1.hexdigest(array.join)
    result
  end

  #消息签名
  def sig_wx_message(wx_token, timestamp, nonce, msg_encrypt)
    array = [wx_token, timestamp, nonce, msg_encrypt].sort
    Digest::SHA1.hexdigest(array.join)
    #signature
  end

  #消息签名验证,也可用于企业号开启回调模式
  def verify_wx_message(signature,wx_token, timestamp, nonce, msg_encrypt)
    array = [wx_token, timestamp, nonce, msg_encrypt].sort
    result= 0
    result= 1 if signature == Digest::SHA1.hexdigest(array.join)
    result
  end

end