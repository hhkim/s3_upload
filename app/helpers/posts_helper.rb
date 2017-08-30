module PostsHelper
  # AWS_ACCESS_KEY_ID = 'AKIAIMQ5V4CNVJ5VYKIQ'
  # AWS_SECRET_ACCESS_KEY = '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'
  # S3_REGION = 'ap-northeast-2'
  # S3_BUCKET= 's3-direct'
  
  # s3_upload_form(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, S3_REGION, S3_BUCKET)
  def s3_upload_form(key=nil, prefix=nil)
    access_key = 'AKIAIMQ5V4CNVJ5VYKIQ'
    secret_key = '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'
    region = 'ap-northeast-2'
    bucket = 's3-direct'
    
    raise "" unless key != nil or prefix != nil
    if key != nil and prefix != nil
      raise "key is not start with prefix" unless key.start_with? prefix
    end

    now = Time.now
    form = {
      'acl': 'private',
      'success_action_status': '200',
      'x-amz-algorithm': 'AWS4-HMAC-SHA256',
      'x-amz-credential': "#{access_key}/#{now.strftime('%Y%m%d')}/#{region}/s3/aws4_request",
      'x-amz-date': now.strftime('%Y%m%dT000000Z')
    }
    expiration = now + 30.minutes
    policy = {
      'expiration': expiration.strftime('%Y-%m-%dT%H:%M:%SZ'),
      'conditions': [
        {'bucket': bucket},
        {'acl': 'private'},
        ['content-length-range', 32, 10485760 * 1024],
        {'success_action_status': form[:'success_action_status']},
        {'x-amz-algorithm':       form[:'x-amz-algorithm']},
        {'x-amz-credential':      form[:'x-amz-credential']},
        {'x-amz-date':            form[:'x-amz-date']},
      ]
    }

    form[:'action'] = "https://#{bucket}.s3-#{region}.amazonaws.com/"
    if key != nil
      form[:'key'] = key
      policy[:'conditions'] = policy[:'conditions'].append('key': key)
    end

    if prefix != nil
      form[:'prefix'] = prefix
      policy[:'conditions'] = policy[:'conditions'].append(["starts-with", "$key", prefix])
    end

    form[:'policy'] = Base64.encode64(policy.to_json).gsub("\n", "")
    form[:'x-amz-signature'] = sign(secret_key, now, region, 's3', form[:'policy'])
    form
  end
  
  def sign(key, date, region, service, msg)
    date  = date.strftime('%Y%m%d')
    hash1 = hmac('AWS4'+key, date)
    hash2 = hmac(hash1, region)
    hash3 = hmac(hash2, service)
    key   = hmac(hash3, 'aws4_request')
    hexhmac(key, msg)
  end

  def hmac(key, value)
    OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), key, value)
  end

  def hexhmac(key, value)
    OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'), key, value)
  end
end
