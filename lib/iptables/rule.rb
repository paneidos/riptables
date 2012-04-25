module IPTables
  class Rule
    class << self
      def add_custom_matcher(name,flag=nil,&block)
        if flag.nil? && name.is_a?(Hash)
          flag = name.values.first
          name = name.keys.first
        end
        define_method "add_#{name}" do |arg|
          instance_variable_set "@#{name}", arg
          add_matcher name.to_sym unless @matchers.include? name.to_sym
        end
        if block_given?
          define_method "get_#{name}_matcher", &block
        elsif flag.nil?
          define_method "get_#{name}_matcher" do
            raise "Unimplemented method 'get_#{name}_matcher'"
          end
        else
          define_method "get_#{name}_matcher" do
            [ flag, instance_variable_get("@#{name}") ]
          end
        end
      end
      def add_custom_matchers(*args)
        hash = nil
        if args.last.is_a?(Hash)
          hash = args.pop
        end
        args.each do |arg|
          add_custom_matcher arg
        end
        unless hash.nil?
          hash.each do |arg,flag|
            add_custom_matcher arg,flag
          end
        end
      end
      def has_invertable(name)
        define_method "not_#{name}" do |*args,&block|
          send(name,*args,&block)
          set_inverted name
        end
      end
    end
    
    POSSIBLE_STATES = [ :NEW, :INVALID, :ESTABLISHED, :RELATED ]
    
    def initialize(chain)
      @chain = chain
      # @requirements = []
      @inverted = {}
      @matchers = []
      @proto = nil
      @interface_in = nil
      @interface_out = nil
      @target = nil
      @goto = false
      @modules = []
    end
    
    def dup
      newrule = super
      newrule.instance_eval do
        @matchers = @matchers.dup
        @modules = @modules.dup
      end
      newrule
    end
    
    def goto(chain,opts={})
      set_next_chain chain,true,opts
    end
    
    def call(chain,opts={})
      set_next_chain chain,false,opts
    end
    
    alias :jump :call
    
    def accept
      jump :ACCEPT
    end
    
    def drop
      jump :DROP
    end
    
    def reject(options={})
      newopts = {}
      newopts[:reject_with] = options[:with].to_s.gsub('_','-') if options[:with]
      jump :REJECT, newopts
    end
    
    def log(options={})
      newopts = {}
      newopts[:log_prefix] = options[:prefix] if options[:prefix]
      jump :LOG, newopts
    end
    
    def limit(rate,options={},&block)
      newrule = dup
      newrule.add_module :limit
      burst = nil
      burst = options[:burst] if options[:burst]
      newrule.add_limit [rate,burst]
      newrule.instance_eval &block
    end
    
    def interface_in(iface,&block)
      newrule = dup
      newrule.add_interface_in iface
      newrule.instance_eval &block
    end
    
    def interface_out(iface,&block)
      newrule = dup
      newrule.add_interface_out iface
      newrule.instance_eval &block
    end
    
    def interface iface, &block
      interface_out iface, &block
      interface_in iface, &block
    end
    
    def proto(protocol,&block)
      newrule = dup
      newrule.add_proto protocol
      newrule.instance_eval &block
    end
    
    def state(*states,&block)
      states.flatten!
      raise "Invalid states: #{(states - POSSIBLE_STATES).map(&:to_s).join ','}" if (states-POSSIBLE_STATES).size > 0
      newrule = dup
      newrule.add_module :state
      newrule.add_state states
      newrule.instance_eval &block
    end
    
    def isolate(&block)
      newrule = dup
      newrule.instance_eval &block
    end
    
    def destination(addr,&block)
      newrule = dup
      newrule.add_destination addr
      newrule.instance_eval &block
    end

    def source(addr,&block)
      newrule = dup
      newrule.add_source addr
      newrule.instance_eval &block
    end
    
    def udp(options={},&block)
      newrule = dup
      newrule.add_proto :udp
      newrule.add_module :udp
      options.each do |key,value|
        m = ["--#{key.to_s.gsub(/^!/,'').gsub('_','-')}", value]
        m.pop if value === true
        m.unshift "!" if key.to_s[0..0] == "!"
        newrule.add_matcher m
      end
      newrule.instance_eval &block
    end
    
    def tcp(options={},&block)
      newrule = dup
      newrule.add_proto :tcp
      newrule.add_module :tcp
      options.each do |key,value|
        m = ["--#{key.to_s.gsub(/^!/,'').gsub('_','-')}", value]
        m.pop if value === true
        m.unshift "!" if key.to_s[0..0] == "!"
        newrule.add_matcher m
      end
      newrule.instance_eval &block
    end
    
    def to_command
      matchers = @matchers.map do |matcher|
        if matcher.is_a?(Symbol)
          send("get_#{matcher}_matcher")
        else
          matcher
        end
      end
      target = []
      target << (@goto ? "-g" : "-j")
      target << @target[:chain]
      @target[:opts].each do |key,value|
        if value === true
          target << [ "--#{key.to_s.gsub('_','-')}" ]
        else
          target << [ "--#{key.to_s.gsub('_','-')}", value ]
        end
      end
      (matchers.flatten + target.flatten).join " "
    end
    
    has_invertable :state
    
    protected
    
    add_custom_matcher :proto, "-p"
    add_custom_matchers :interface_in => "-i", :interface_out => "-o"
    add_custom_matcher :destination => "-d"
    add_custom_matcher :source => "-s"
    
    add_custom_matcher :state do
      res = [ "--state", @state.join(",") ]
      res.unshift "!" if @inverted[:state]
      res
    end
    
    add_custom_matcher :limit do
      res = [ "--limit", @limit.first ]
      res << ["--limit-burst", @limit.last ] if @limit.last
      res.flatten
    end
    
    def add_matcher(matcher)
      @matchers << matcher
    end
    
    def add_requirement(requirement)
      @requirements << requirement
    end
    
    def add_module(module_name)
      return if @modules.include?(module_name)
      @modules << module_name
      @matchers << [ "-m", module_name ]
    end
    
    def set_inverted(target)
      @inverted[target.to_sym] = true
    end
    
    def set_next_chain(chain,goto=false,opts={})
      raise "Invalid chain called: #{chain}" unless @chain.can_call_chain?(chain)
      newrule = dup
      newrule.instance_eval do
        @target = {
          :chain => chain,
          :opts => opts
        }
        @goto = goto
      end
      @chain.add_rule newrule
    end
  end
end