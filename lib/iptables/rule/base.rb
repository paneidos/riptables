module IPTables
  class Rule
    class Base
      class << self
        def normal(*args)
          self.new(*args)
        end
        
        def inverted(*args)
          x = self.new(*args)
          x.instance_eval do
            @inverted = true
          end
        end
      end
      
      attr_accessor :inverted
      
      def command_options
        []
      end
      
      def required_modules
        []
      end
    end
  end
end