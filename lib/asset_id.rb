require 'digest/md5'
require 'mime/types'
require 'aws/s3'
require 'time'
require 'digest/sha1'
require 'net/https'
require 'base64'

module AssetID
  
  class Base
    DEFAULT_ASSET_PATHS = ['favicon.ico', 'images', 'javascripts', 'stylesheets']
    @@asset_paths = DEFAULT_ASSET_PATHS
    
    def self.path_prefix
      File.join Rails.root, 'public'
    end
    
    def self.asset_paths=(paths)
      @@asset_paths = paths
    end
    
    def self.asset_paths
      @@asset_paths
    end
    
    def self.absolute_path(path)
      File.join path_prefix, path
    end
    
    def self.assets
      asset_paths.inject([]) {|assets, path|
        path = absolute_path(path)
        assets << path if File.exists? path and !File.directory? path
        assets += Dir.glob(path+'/**/*').inject([]) {|m, file| 
          m << file unless File.directory? file; m 
        }
      }
    end
    
    def self.fingerprint(path)
      path = File.join path_prefix, path unless path =~ /#{path_prefix}/
      d = Digest::MD5.file(path).hexdigest
      path = path.gsub(path_prefix, '')
      File.join File.dirname(path), "#{File.basename(path, File.extname(path))}-id-#{d}#{File.extname(path)}"
    end
    
    def self.original_path(path)
      path = File.join path_prefix, path unless path =~ /#{path_prefix}/
      path = path.gsub(path_prefix, '')
      File.join File.dirname(path), "#{File.basename(path, File.extname(path))}#{File.extname(path)}"
    end
    
  end
  
  class S3 < AssetID::Base
    
    DEFAULT_GZIP_TYPES = ['text/css', 'application/javascript']
    @@gzip_types = DEFAULT_GZIP_TYPES
    
    def self.gzip_types=(types)
      @@gzip_types = types
    end
    
    def self.gzip_types
      @@gzip_types
    end
    
    def self.s3_config
      @@config ||= YAML.load_file(File.join(Rails.root, "config/amazon_s3.yml"))[Rails.env] rescue nil || {}
    end
    
    def self.connect_to_s3
      AWS::S3::Base.establish_connection!(
        :access_key_id => s3_config['access_key_id'],
        :secret_access_key => s3_config['secret_access_key']
      )
    end
    
    def self.cache_headers
      {'Expires' => (Time.now + (60*60*24*365)).httpdate, 'Cache-Control' => 'public'} # 1 year expiry
    end
    
    def self.gzip_headers
      {'Content-Encoding' => 'gzip', 'Vary' => 'Accept-Encoding'}
    end
    
    def self.s3_permissions
      :public_read
    end
    
    def self.s3_bucket
      s3_config['bucket']
    end
    
    def self.fingerprint(path)
      #File.join "/#{self.s3_bucket}", fingerprint(path)
      super(path)
    end
    
    def self.original_path(path)
      super(path)
    end
    
    def self.upload(options={})
      connect_to_s3
      assets.each do |asset|
        puts "asset_id: Uploading #{asset} as #{fingerprint(asset)}" if options[:debug]
        mime_type = MIME::Types.of(asset).first.to_s
        
        headers = {
          :content_type => mime_type,
          :access => s3_permissions,
        }.merge(cache_headers)
        
        if gzip_types.include? mime_type
          data = `gzip -c "#{asset}"`
          headers.merge!(gzip_headers)
        else
          data = File.read(asset)
        end
        
        puts "asset_id: headers: #{headers.inspect}" if options[:debug]
        
        # Store object without asset-id as well for css stylesheets
        AWS::S3::S3Object.store(
          original_path(asset),
          data,
          s3_bucket,
          headers
        ) unless options[:dry_run]
        
        AWS::S3::S3Object.store(
          fingerprint(asset),
          data,
          s3_bucket,
          headers
        ) unless options[:dry_run]
      end
    end
    
    def self.invalidate(options={})
      connect_to_s3
      paths = ""
      assets.each do |asset|
        paths += "<Path>#{original_path(asset)}</Path>"
        paths += "<Path>#{fingerprint(asset)}</Path>" unless options[:original_only]
      end
      digest = OpenSSL::Digest.new('sha1')
      digest = OpenSSL::HMAC.digest(digest, s3_config['secret_access_key'], date = Time.now.utc.strftime("%a, %d %b %Y %H:%M:%S %Z"))
      uri = URI.parse("https://cloudfront.amazonaws.com/2010-11-01/distribution/#{s3_config['cloudfront_distribution_id']}/invalidation")
      req = Net::HTTP::Post.new(uri.path)
      req.initialize_http_header({
        'x-amz-date' => date,
        'Content-Type' => 'text/xml',
        'Authorization' => "AWS %s:%s" % [s3_config['access_key_id'], Base64.encode64(digest)]
      })
      req.body = "<InvalidationBatch>#{paths}<CallerReference>asset_id_#{Time.now.utc.to_i}</CallerReference></InvalidationBatch>"
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      res = http.request(req)
      puts res.code == '201' ? 'Assets Invalidated' : "Failed #{res.code}"
    end
    
  end
end
