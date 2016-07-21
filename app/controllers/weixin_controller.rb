class WeixinController < ApplicationController
  protect_from_forgery :except => [:index, :mp]
  def index
    wx_token="LBY3LxW0C"
    aes_key="Ea46PFmr5gaA"
    corpid="wx4ec22"
    timestamp=URI::decode(params[:timestamp])
    nonce=URI::decode(params[:nonce])
    msg_signature=URI::decode(params[:msg_signature])

    xmlbody=request.body.read.to_s
    # obj = JSON.parse(we)
    xmldoc = Document.new(xmlbody).root


    if params[:echostr].nil?
      msg_encrypt=xmldoc.elements["Encrypt"].text
    else
      #首次接入
      msg_encrypt=URI::decode(params[:echostr])
      render :text => Weixin_aes.new.decrypt(aes_key, msg_encrypt, corpid) if Weixin_aes.new.verify_wx_message(msg_signature, wx_token, timestamp, nonce, msg_encrypt) == 1

      Rails.logger.debug("#{__FILE__}:#{__LINE__} 签名有效性 #{Weixin_aes.new.decrypt(aes_key, msg_encrypt, corpid)} ")
    end

    if params[:echostr].nil?
    sig=Weixin_aes.new.verify_wx_message(msg_signature, wx_token, timestamp, nonce, msg_encrypt)

    Rails.logger.debug("#{__FILE__}:#{__LINE__} 签名有效性 #{sig} ")
    if sig == 1 then
      messagexml=Weixin_aes.new.decrypt(aes_key, msg_encrypt, corpid)
      messagexmldoc = Document.new(messagexml).root
      content= messagexmldoc.elements["Content"].text

      replymessage="<xml>"
      replymessage+="<ToUserName><![CDATA[#{messagexmldoc.elements["FromUserName"].text}]]></ToUserName>"
      replymessage+="<FromUserName><![CDATA[#{messagexmldoc.elements["ToUserName"].text}]]></FromUserName>"
      replymessage+="<CreateTime>#{Time.now.to_i}</CreateTime>"
      replymessage+="<MsgType><![CDATA[text]]></MsgType>"
      replymessage+="<Content><![CDATA[#{content}]]></Content>"
      replymessage+="</xml>"


      Rails.logger.debug("#{__FILE__}:#{__LINE__} 构造的消息xml #{replymessage} ")

      msgEncrypt=Weixin_aes.new.encrypt(aes_key, replymessage, corpid)
      msgdecrypt=Weixin_aes.new.decrypt(aes_key, msgEncrypt, corpid)
      msgdecrypt=Document.new(msgdecrypt).root
      Rails.logger.debug("#{__FILE__}:#{__LINE__} 加密构造的xml #{msgEncrypt}")
      Rails.logger.debug("#{__FILE__}:#{__LINE__} 解密上面加密的xml #{msgdecrypt}")

      timesig=Time.now.to_i.to_s

      Rails.logger.debug("#{__FILE__}:#{__LINE__} 回复签名时间 #{timesig} ")
      sigmsg=Weixin_aes.new.sig_wx_message(wx_token, timesig, nonce, msgEncrypt)
      replymsg="<xml>"
      replymsg+="<Encrypt><![CDATA[#{msgEncrypt}]]></Encrypt>"
      replymsg+="<MsgSignature><![CDATA[#{sigmsg}]]></MsgSignature>"
      replymsg+="<TimeStamp>#{timesig}</TimeStamp>"
      replymsg+="<Nonce><![CDATA[#{nonce}]]></Nonce>"
      replymsg+="</xml>"
      render :text => replymsg
      Rails.logger.debug("#{__FILE__}:#{__LINE__} 输出 #{replymsg} ")
    end
    end

  end

  def mp

    wx_token="LBY3LxW0C"
    aes_key="Ea46G8VzPF"
    corpid="wx0311"
    timestamp=URI::decode(params[:timestamp])
    nonce=URI::decode(params[:nonce])
    signature=URI::decode(params[:signature])


    xmlbody=request.body.read.to_s
    # obj = JSON.parse(we)
    xmldoc = Document.new(xmlbody).root

    if params[:echostr].nil?
      msg_signature=URI::decode(params[:msg_signature])
      msg_encrypt=xmldoc.elements["Encrypt"].text
    else
      #首次接入
      msg_encrypt=URI::decode(params[:echostr])
      render :text => msg_encrypt if Weixin_aes.new.verify_wx_url(signature, wx_token, timestamp, nonce) == 1
    end

    sig=Weixin_aes.new.verify_wx_message(msg_signature, wx_token, timestamp, nonce, msg_encrypt)

    Rails.logger.debug("#{__FILE__}:#{__LINE__} 密文 #{msg_encrypt} ")
    Rails.logger.debug("#{__FILE__}:#{__LINE__} 签名有效性 #{sig} ")
    if sig == 1 then
      messagexml=Weixin_aes.new.decrypt(aes_key, msg_encrypt, corpid)
      messagexmldoc = Document.new(messagexml).root
      content= messagexmldoc.elements["Content"].text

      replymessage="<xml>"
      replymessage+="<ToUserName><![CDATA[#{messagexmldoc.elements["FromUserName"].text}]]></ToUserName>"
      replymessage+="<FromUserName><![CDATA[#{messagexmldoc.elements["ToUserName"].text}]]></FromUserName>"
      replymessage+="<CreateTime>#{Time.now.to_i}</CreateTime>"
      replymessage+="<MsgType><![CDATA[text]]></MsgType>"
      replymessage+="<Content><![CDATA[弹回:#{content}]]></Content>"
      replymessage+="</xml>"

      msgEncrypt=Weixin_aes.new.encrypt(aes_key, replymessage, corpid)
      msgdecrypt=Weixin_aes.new.decrypt(aes_key, msgEncrypt, corpid)
      msgdecrypt=Document.new(msgdecrypt).root
      Rails.logger.debug("#{__FILE__}:#{__LINE__} 加密构造的xml #{msgEncrypt}")
      Rails.logger.debug("#{__FILE__}:#{__LINE__} 解密上面加密的xml #{msgdecrypt}")

      timesig=Time.now.to_i.to_s

      Rails.logger.debug("#{__FILE__}:#{__LINE__} 回复签名时间 #{timesig} ")
      sigmsg=Weixin_aes.new.sig_wx_message(wx_token, timesig, nonce, msgEncrypt)
      replymsg="<xml>"
      replymsg+="<Encrypt><![CDATA[#{msgEncrypt}]]></Encrypt>"
      replymsg+="<MsgSignature><![CDATA[#{sigmsg}]]></MsgSignature>"
      replymsg+="<TimeStamp>#{timesig}</TimeStamp>"
      replymsg+="<Nonce><![CDATA[#{nonce}]]></Nonce>"
      replymsg+="</xml>"
      render :text => replymsg
      Rails.logger.debug("#{__FILE__}:#{__LINE__} 输出 #{replymsg} ")
    end

  end

end
