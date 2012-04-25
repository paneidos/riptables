module IPTables
  class Base
    def initialize
      @tables = {}
      @recipes = []
      @custom_methods = {}
      @compiled = false
    end
    
    def print(only_table=nil,only_chain=nil)
      compile
      puts "# Tables: #{@tables.keys.join ','}"
      @tables.each do |table_name,table|
        if only_table.nil? or only_table.to_s == table_name.to_s
          puts "# Table '#{table_name}'"
          table.print only_chain
        end
      end
    end
    
    def configure(file = nil,&block)
      obj = Object.new
      tables = @tables
      recipes = @recipes
      custom_methods = @custom_methods
      obj.define_singleton_method :define_rule do |name,&block|
        custom_methods[name] = block
        obj.define_singleton_method name,&block
      end
      custom_methods.each do |name,block|
        obj.define_singleton_method name,&block
      end
      obj.define_singleton_method :import do |recipe|
        obj.instance_eval File.open(File.expand_path("../iptables/recipes/#{recipe}.rb",__FILE__),"r") { |f| f.read }
      end
      obj.define_singleton_method :table do |name, &table_block|
        tables[name.intern] ||= Table.new name
        tables[name.intern].add_block &table_block
      end
      if file
        data = File.open(file,"r") { |f| f.read }
        obj.instance_eval(data)
      else
        obj.instance_eval &block
      end
    end
    
    def compile
      return if @compiled
      @compiled = true
      @tables.each do |name,table|
        table.configure
      end
    end
  end
  
  autoload :Table, File.expand_path("../iptables/table",__FILE__)
  autoload :Chain, File.expand_path("../iptables/chain",__FILE__)
  autoload :Rule, File.expand_path("../iptables/rule",__FILE__)
end