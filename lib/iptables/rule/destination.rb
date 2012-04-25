module IPTables
  class Rule
    class Destination < Base
      def initialize(destination)
        @destination = destination
      end
      
      def command_options
        opts = [ "-d", destination ]
        opts.unshift "!" if @inverted
        opts
      end
    end
  end
end