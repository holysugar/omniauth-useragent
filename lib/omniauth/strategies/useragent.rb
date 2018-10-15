require "omniauth/useragent/version"
require "omniauth"
require "digest/sha2"

module OmniAuth
  module Strategies
    class Useragent
      include OmniAuth::Strategy

      option :allow
      option :deny

      attr_accessor :user_agent

      def setup_phase
        super
      end

      def request_phase
        redirect callback_path
      end

      def callback_phase
        return fail!(:invalid_credentials) unless allow?
        return fail!(:invalid_credentials) if deny?

        self.user_agent = raw_user_agent

        super
      end

      def uid
        Digest::SHA256.hexdigest user_agent if user_agent
      end

      def info
        {
          name: user_agent,
          useragent: user_agent
        }
      end

      private

      def raw_user_agent
        env["HTTP_USER_AGENT"]
      end

      def allow?
        return true if options[:allow].nil?
        Array(options[:allow]).any? do |item|
          item === raw_user_agent
        end
      end

      def deny?
        return false if options[:deny].nil?
        Array(options[:deny]).any? do |item|
          item === raw_user_agent
        end
      end
    end
  end
end
