#!/usr/bin/env ruby

# Copyright (C) 2014 RoboVM AB
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/gpl-2.0.html>.
#

require 'ffi/clang'
require 'yaml'
require 'fileutils'
require 'pathname'
require 'tmpdir'

class String
    def camelize
        dup.camelize!
    end

    def camelize!
        replace(split('_').each(&:capitalize!).join(''))
    end

    def downcase_first_camelize
        dup.downcase_first_camelize!
    end

    def downcase_first_camelize!
        camelize!
        downcase_first
        self
    end

    def upcase_first_camelize
        dup.upcase_first_camelize!
    end

    def upcase_first_camelize!
        camelize!
        upcase_first
        self
    end

    def underscore
        dup.underscore!
    end

    def underscore!
        replace(scan(/[A-Z][a-z]*/).join('_').downcase)
    end

    def upcase_first
        self[0] = self[0].upcase
        self
    end

    def downcase_first
        self[0] = self[0].downcase
        self
    end
end

module Bro
    def self.location_to_id(location)
        "#{location.file}:#{location.offset}"
    end

    def self.location_to_s(location)
        "#{location.file}:#{location.line}:#{location.column}"
    end

    def self.read_source_range(sr)
        file = sr.start.file
        if file
            start = sr.start.offset
            n = sr.end.offset - start
            bytes = nil
            open file, 'r' do |f|
                f.seek start
                bytes = f.read n
            end
            bytes.to_s
        else
            '?'
        end
    end

    def self.read_attribute(cursor)
        Bro.read_source_range(cursor.extent)
    end

    class Entity

        attr_accessor :id, :location, :name, :framework, :attributes, :cursor
        def initialize(model, cursor)
            @cursor = cursor
            @location = cursor ? cursor.location : nil
            @id = cursor ? Bro.location_to_id(@location) : nil
            @name = cursor ? cursor.spelling : nil
            @model = model
            @framework = @location ?
                @location.file.to_s.split(File::SEPARATOR).reverse.find_all { |e| e.match(/^.*\.(framework|lib)$/) }.map { |e| e.sub(/(.*)\.(framework|lib)/, '\1') }.first :
                nil
            @attributes = []
        end

        def types
            []
        end

        def java_name
            name ? ((@model.get_class_conf(name) || {})['name'] || name) : ''
        end

        def pointer
            Pointer.new self
        end

        def is_available?
            # check if directly unavailable
            attrib = @attributes.find { |e| e.is_a?(UnavailableAttribute) }
            return false if attrib

            # check if available
            attrib = @attributes.find { |e| e.is_a?(AvailableAttribute) && e.platform == $target_platform }
            if attrib
                # availability for $target_platform specified 
                # -1 means that is not available for this platform 
                return attrib.version == nil || (attrib.version != -1 && attrib.version <= $ios_version.to_f)
            end
            attrib = @attributes.find { |e| e.is_a?(AvailableAttribute) && e.platform == nil && e.version != nil }
            if attrib
                # availability without platform but with version 
                return attrib.version != -1 && attrib.version <= $ios_version.to_f
            end

            # nothing specified so available
            true
        end

        def is_outdated?
            if deprecated
                d_version = deprecated
                (d_version > 0 && d_version <= @model.min_usable_version) || (d_version < 0 && @model.exclude_deprecated?)
            else
                false
            end
        end

        def since
            attrib = @attributes.find { |e| e.is_a?(AvailableAttribute) && e.version != nil && (e.platform == nil || e.platform == $target_platform) }
            attrib.version if attrib
        end

        def deprecated
            attrib = @attributes.find { |e| e.is_a?(AvailableAttribute) && e.dep_version != nil && (e.platform == nil || e.platform == $target_platform) }
            attrib.dep_version if attrib
        end

        def reason
            attrib = @attributes.find { |e| e.is_a?(AvailableAttribute) && e.dep_message != nil && (e.platform == nil || e.platform == $target_platform) }
            attrib.dep_message if attrib
        end

        def valueAttributeForKey(key)
            attrib = @attributes.find { |e| e.is_a?(KeyValueAttribute) && e.key == key }
            attrib.value if attrib
        end
        def full_name
            @name
        end
    end

    class Pointer < Entity
        attr_accessor :pointee
        def initialize(pointee)
            super(nil, nil)
            @pointee = pointee
        end

        def types
            @pointee.types
        end

        def java_name
            if @pointee.is_a?(Builtin)
                if %w(byte short char int long float double boolean void).include?(@pointee.name)
                    "#{@pointee.name.capitalize}Ptr"
                elsif @pointee.name == 'MachineUInt'
                    'MachineSizedUIntPtr'
                elsif @pointee.name == 'MachineSInt'
                    'MachineSizedSIntPtr'
                elsif @pointee.name == 'MachineFloat'
                    'MachineSizedFloatPtr'
                elsif @pointee.name == 'Pointer'
                    'VoidPtr.VoidPtrPtr'
                else
                    "#{@pointee.java_name}.#{@pointee.java_name}Ptr"
                end
            elsif @pointee.is_a?(Struct) || @pointee.is_a?(Typedef) && @pointee.is_struct? || @pointee.is_a?(ObjCClass) || @pointee.is_a?(ObjCProtocol)
                @pointee.java_name
            else
                "#{@pointee.java_name}.#{@pointee.java_name}Ptr"
            end
        end
    end

    class Array < Entity
        attr_accessor :base_type, :dimensions
        def initialize(base_type, dimensions)
            super(nil, nil)
            @base_type = base_type
            @dimensions = dimensions
        end

        def types
            @base_type.types
        end

        def java_name
            if @base_type.is_a?(Builtin)
                if %w(byte short char int long float double).include?(@base_type.name)
                    "#{@base_type.name.capitalize}Buffer"
                elsif @base_type.name == 'MachineUInt'
                    'MachineSizedUIntPtr'
                elsif @base_type.name == 'MachineSInt'
                    'MachineSizedSIntPtr'
                elsif @base_type.name == 'MachineFloat'
                    'MachineSizedFloatPtr'
                elsif @base_type.name == 'Pointer'
                    'VoidPtr.VoidPtrPtr'
                else
                    "#{@base_type.java_name}.#{@base_type.java_name}Ptr"
                end
            elsif @base_type.is_a?(Struct) || @base_type.is_a?(Typedef) && @base_type.is_struct?
                @base_type.java_name
            else
                "#{@base_type.java_name}.#{@base_type.java_name}Ptr"
            end
        end
    end

    class Block < Entity
        attr_accessor :return_type, :param_types
        def initialize(model, return_type, param_types)
            super(model, nil)
            @return_type = return_type
            @param_types = param_types || []
        end

        def types
            [@return_type.types] + @param_types.map(&:types)
        end

        @@simple_block_types = {'boolean' => 'Boolean', 'byte' => 'Byte',
            'short' => 'Short', 'char' => 'Character', 'int' => 'Integer',
            'long' => 'Long', 'float' => 'Float', 'double' => 'Double',
            # and also annotated types
            '@MachineSizedUInt long' => 'Long','@MachineSizedSInt long' => 'Long',
            '@MachineSizedFloat double' => 'Double'}
        @@simple_block_types_anotat = {'@MachineSizedUInt long' => '@MachineSizedUInt',
            '@MachineSizedSInt long' => '@MachineSizedSInt', '@MachineSizedFloat double' => '@MachineSizedFloat'}
        def java_name
            res = java_name_ex()
            return res[0] + ' ' + res[1]
        end

        # modified to return array tuple to be able create block type param inside block
        def java_name_ex
            if @return_type.is_a?(Builtin) && @return_type.name == 'void'
                if @param_types.empty?
                    ['@Block', 'Runnable']
                elsif @param_types.size == 1 && @param_types[0].is_a?(Builtin) && @@simple_block_types[@param_types[0].name]
                    ["@Block", "Void#{@param_types[0].name.capitalize}Block"]
                elsif @param_types.size <= 6
                    by_val_params = to_by_val_params(@param_types).join(",")
                    by_val_mark = ''
                    by_val_mark = "(\"(#{by_val_params})\")" if !by_val_params.gsub(',', '').empty?
                    ["@Block#{by_val_mark}", "VoidBlock#{@param_types.size}<" + @param_types.map { |e| to_java_name(e) }.join(", ") + ">"]
                else
                    ['', 'ObjCBlock']
                end
            else
                if @param_types.size == 0 && @return_type.is_a?(Builtin) && @@simple_block_types[@return_type.name]
                    ["@Block", "#{@return_type.name.capitalize}Block"]
                elsif @param_types.size <= 6
                    # besides @ByVal it would be required to replace @MachineSized anotated
                    # types with proper types and add these annotations to by_val_params
                    by_val_params = to_by_val_params(@param_types).join(",")
                    by_val_mark = ''
                    by_val_mark = "(\"(#{by_val_params})\")" if !by_val_params.gsub(',', '').empty?
                    ["@Block#{by_val_mark}", "Block#{@param_types.size}<" + @param_types.map { |e| to_java_name(e) }.push(to_java_name(return_type)).join(", ") + ">"]
                else
                    ['', 'ObjCBlock']
                end
            end
        end

        def to_by_val_params(p_types)
            p_types.map {|e|
                if @model.is_byval_type?(e)
                    '@ByVal'
                elsif e.is_a?(Block)
                    '@Block'
                elsif e.is_a?(Builtin)
                    @@simple_block_types_anotat[e.java_name] || ''
                else
                    ''
                end
            }
        end

        def to_java_name(type)
            if type.respond_to?('each') # Generic type
                @model.to_java_generic_type(type)
            elsif type.is_a?(Block)
                type.java_name_ex()[1]
            else
                @@simple_block_types[type.java_name] || type.java_name
            end
        end
    end

    class ObjCId < Entity
        attr_accessor :protocols
        def initialize(model, protocols)
            super(model, nil)
            @protocols = protocols
        end

        def types
            @protocols.map(&:types)
        end

        def java_name
            # filter protocols that are only available 
            pp = @protocols.find_all do |prot|
                c = @model.get_protocol_conf(prot.name)
                next unless c && !c['skip_implements']
                prot
            end
            pp.map(&:java_name).join(' & ')
        end
    end

    class Builtin < Entity
        attr_accessor :name, :type_kinds, :java_name, :storage_type
        def initialize(name, type_kinds = [], java_name = nil, storage_type = nil)
            super(nil, nil)
            @name = name
            @type_kinds = type_kinds
            @java_name = java_name || name
            @storage_type = storage_type || name
        end
    end

    @@builtins = [
        Builtin.new('boolean', [:type_bool]),
        Builtin.new('byte', [:type_uchar], nil, 'unsigned char'),
        Builtin.new('byte', [:type_schar, :type_char_s], nil, 'signed char'),
        Builtin.new('short', [:type_short], nil, 'signed short'),
        Builtin.new('short', [:type_ushort], nil, 'unsigned short'),
        Builtin.new('char', [:type_wchar, :type_char16], nil, 'unsigned short'),
        Builtin.new('int', [:type_int], nil, 'signed int'),
        Builtin.new('int', [:type_uint, :type_char32], nil, 'unsigned int'),
        Builtin.new('long', [:type_longlong], nil, 'signed long'),
        Builtin.new('long', [:type_ulonglong], nil, 'unsigned long'),
        Builtin.new('float', [:type_float]),
        Builtin.new('double', [:type_double]),
        Builtin.new('MachineUInt', [:type_ulong], '@MachineSizedUInt long'),
        Builtin.new('MachineSInt', [:type_long], '@MachineSizedSInt long'),
        Builtin.new('MachineFloat', [], '@MachineSizedFloat double'),
        Builtin.new('void', [:type_void]),
        Builtin.new('Pointer', [], '@Pointer long'),
        Builtin.new('String', [], 'String'),
        Builtin.new('__builtin_va_list', [], 'VaList'),
        Builtin.new('ObjCBlock', [:type_block_pointer]),
        Builtin.new('FunctionPtr', [], 'FunctionPtr'),
        Builtin.new('Selector', [:type_obj_c_sel], 'Selector'),
        Builtin.new('ObjCObject', [], 'ObjCObject'),
        Builtin.new('ObjCClass', [], 'ObjCClass'),
        Builtin.new('ObjCProtocol', [], 'ObjCProtocol'),
        Builtin.new('BytePtr', [], 'BytePtr')
    ]
    @@builtins_by_name = @@builtins.each_with_object({}) { |b, h| h[b.name] = b; h }
    @@builtins_by_type_kind = @@builtins.each_with_object({}) { |b, h| b.type_kinds.each { |e| h[e] = b }; h }
    def self.builtins_by_name(name)
        @@builtins_by_name[name]
    end

    def self.builtins_by_type_kind(kind)
        @@builtins_by_type_kind[kind]
    end

    class Attribute
        attr_accessor :source
        def initialize(source)
            @source = source
        end
    end
    class IgnoredAttribute < Attribute
        def initialize(source)
            super(source)
        end
    end
    # attribute to attach important data
    class KeyValueAttribute < Attribute
        attr_accessor :key, :value
        def initialize(source)
            super(source)
            source =~ /^(.*?)\("?(.*?)"?\)$/
            @key = $1
            @value = $2
        end
    end
    class AvailableAttribute < Attribute
        attr_accessor :platform, :version, :dep_version, :dep_message
        def initialize(source)
            super(source)
            @dep_message = []
            if source.start_with?('availability(')
                source = source.split("\n").collect{|x| x.strip || x}.join("").gsub("\"\"", "")
                source =~ /^availability\((.*)\)/
                args = $1.split(/,(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)/).collect{|x| x.strip || x}
                @platform = args[0]
                args[1..-1].each do |v|
                    if v == 'unavailable'
                        @version = -1
                    elsif v.start_with?('introduced=')
                        @version = str_to_float(v.sub('introduced=', '').sub('_', '.'))
                    elsif v.start_with?('deprecated=')
                        @dep_version = str_to_float(v.sub('deprecated=', '').sub('_', '.'))
                    elsif v.start_with?('message=') && v.end_with?('"')
                        m = v.sub('message=', '').strip
                        if (m.start_with?('"') && m.end_with?('"'))
                            m = eval(m).strip
                            @dep_message.push m unless m.empty?
                        end
                    elsif v.start_with?('replacement="') && v.end_with?('"')
                        m = v.sub('replacement=', '')[0..-1]
                        m = eval(m).strip
                        @dep_message.push decorate_dep_replacement(m) unless m.empty? || m.downcase.start_with?("Use ")
                    end
                end
            else
                # deprecated case 
                @dep_version = -1
                source = source.sub('__deprecated__', 'deprecated') if source.start_with?('__deprecated__')
                if source.start_with?('deprecated(')
                    # has message
                    source =~ /^deprecated\((.*)\)/m
                    msg = $1.gsub("\n", '')
                    args = msg.split(/,(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)/m).collect{|x| eval(x).strip || x}
                    if args.length == 2
                        # special case: message + replacement
                        @dep_message.push args[0] unless args[0].empty?
                        @dep_message.push decorate_dep_replacement(args[1]) unless args[1].empty?
                    else 
                        # common case 
                        args.each { |m| @dep_message.push m unless m.empty? }
                    end
                end
            end
            if @dep_message && !@dep_message.empty?
                @dep_message = @dep_message.join(". ")
            else
                @dep_message = nil
            end
        end

        def decorate_dep_replacement(s)
            m = s.downcase
            if m.start_with?("use ") || m.start_with?(" instead")
                s
            else
                # using just single "Use" (without instead) to minimize amount of diffs
                "Use #{s}"
            end
        end

        def str_to_float(s)
            begin
                return -1 if s == "NA"
                return Float(s).to_f
            rescue
                return nil
            end
        end
    end
    class UnavailableAttribute < Attribute
    end
    class UnsupportedAttribute < Attribute
        def initialize(source)
            super(source)
        end
    end

    def self.parse_attribute(cursor)
        source = Bro.read_source_range(cursor.extent)
        if source.start_with?('availability(') || source.start_with?('deprecated(') || source == 'deprecated' || source.start_with?('__deprecated__(') || source == '__deprecated__'
            return AvailableAttribute.new source
        elsif source.start_with?('unavailable')
            return UnavailableAttribute.new source
        # elsif source.start_with?('__DARWIN_ALIAS_C') || source.start_with?('__DARWIN_ALIAS') ||
        #    source == 'CF_IMPLICIT_BRIDGING_ENABLED' || source.start_with?('DISPATCH_') || source.match(/^(CF|NS)_RETURNS_RETAINED/) ||
        #    source.match(/^(CF|NS)_INLINE$/) || source.match(/^(CF|NS)_FORMAT_FUNCTION.*/) || source.match(/^(CF|NS)_FORMAT_ARGUMENT.*/) ||
        #    source == 'NS_RETURNS_INNER_POINTER' || source == 'NS_AUTOMATED_REFCOUNT_WEAK_UNAVAILABLE' || source == 'NS_REQUIRES_NIL_TERMINATION' ||
        #    source == 'NS_ROOT_CLASS' || source == '__header_always_inline' || source.end_with?('_EXTERN') || source.end_with?('_EXTERN_CLASS') || source == 'NSObject' ||
        #    source.end_with?('_CLASS_EXPORT') || source.end_with?('_EXPORT') || source == 'NS_REPLACES_RECEIVER' || source == '__objc_exception__' || source == 'OBJC_EXPORT' ||
        #    source == 'OBJC_ROOT_CLASS' || source == '__ai' || source.end_with?('_EXTERN_WEAK') || source == 'NS_DESIGNATED_INITIALIZER' || source.start_with?('NS_EXTENSION_UNAVAILABLE_IOS') ||
        #    source == 'NS_REQUIRES_PROPERTY_DEFINITIONS' || source.start_with?('DEPRECATED_MSG_ATTRIBUTE') || source == 'NS_REFINED_FOR_SWIFT' || source.start_with?('NS_SWIFT_NAME') ||
        #    source.start_with?('NS_SWIFT_UNAVAILABLE') || source == 'UI_APPEARANCE_SELECTOR' || source == 'CF_RETURNS_NOT_RETAINED' || source == 'NS_REQUIRES_SUPER' || source == 'objc_designated_initializer' ||
        #    source == 'availability' ||  # clang extends property to methods and attaches this attr without proper specification, ignore it
        #    source.start_with?('enum_extensibility') || # appeared in ios11
        #    source.start_with?('ns_error_domain') || source == 'objc_returns_inner_pointer' || # appeared in ios11
        #    source.start_with?('swift_') || # appeared in ios11, ignore all swift4 attr
        #    source.start_with?('NS_OPTIONS') # TODO: there is a lot of such outputs once moved to ios11 due pre-processor workaround. currently just ignoring
        #     return IgnoredAttribute.new source # TODO: lot of these macro are not present anymore as were expanded by pre-clang preprocessor call
        elsif source.start_with?('objc_runtime_name(')
            return KeyValueAttribute.new source
        else
            # return UnsupportedAttribute.new source
            # TODO: there is nothing special about all tese bunch of attributes listed in IgnoredAttribute
            # and UnsupportedAttribute is just making lot of noise in log, just ignore them all
            return IgnoredAttribute.new source
        end
    end

    class Macro
        attr_accessor :name, :source, :args, :body
        def initialize(source)
            source = source.split(/\s*\\*\s*\n/).join(" ")
            @source = source
            # name
            @name = source[/^[A-Za-z_][A-Za-z_0-9]*/]
            # remove name
            s = source.gsub(/^[A-Za-z_][A-Za-z_0-9]*/, '').strip
            # check if has params
            if s.start_with?("(")
                params = s[/^\(.*?\)/][1..-2]
                args = params.scan(/(?:"(?:""|.)*?"(?!")|[^,]*?\(.*?\)|[^,]+)/)
                @args = args.collect{|x| x.strip || x}
                @body = s.sub(/^\(.*?\)\s*/, '')
            else
                @args = []
                @body = s
            end
            # puts "@Macro: #{@name}:  #{@source} #{@args} #{@body}"
            # puts "@Macro: #{@name} && #{@body} ::: #{@source}"
        end

        def subst(params)
            return body unless @args.length
            params = [] unless params
            if params.length != @args.length
                return nil
            end
            res = @body
            for idx in 0..@args.length - 1
                res = res.sub(@args[idx], params[idx])
            end
            return res
        end
    end

    class CallbackParameter
        attr_accessor :name, :type
        def initialize(cursor)
            @name = cursor.spelling
            @type = cursor.type
        end
    end

    class Typedef < Entity
        attr_accessor :typedef_type, :parameters, :struct, :enum
        def initialize(model, cursor, struct_def_name = nil)
            super(model, cursor)
            @parameters = []
            @struct = nil
            @enum = nil

            if struct_def_name
                @name = struct_def_name
                @typedef_type = :type_record
                @is_structDef = true
                return
            end

            @is_structDef = false
            @typedef_type = cursor.typedef_type
            enum_without_name = false
            cursor.visit_children do |cursor, _parent|
                case cursor.kind
                when :cursor_integer_literal
                when :cursor_obj_c_class_ref
                when :cursor_obj_c_protocol_ref
                when :cursor_binary_operator
                when :cursor_paren_expr
                when :cursor_obj_c_independent_class
                    #CXCursor_ObjCIndependentClass          = 427
                    # ignored
                when :cursor_aligned_attr # CXCursor_AlignedAttr = 441
                    # ignored as not able to support right now
                    # example typedef __attribute__((__ext_vector_type__(2),__aligned__(4))) float simd_packed_float2;
                when :cursor_parm_decl
                    @parameters.push CallbackParameter.new cursor
                when :cursor_struct, :cursor_union
                    @struct = Struct.new model, cursor, nil, cursor.kind == :cursor_union
                when :cursor_type_ref
                    if cursor.type.kind == :type_record && @typedef_type.kind != :type_pointer
                        @struct = Struct.new model, cursor, nil, cursor.spelling.match(/\bunion\b/)
                    end
                when :cursor_enum_decl
                    # try to find the enum as it should be created already
                    eid = Bro.location_to_id(cursor.location)
                    e = model.enums.find { |e| e.id == eid}
                    @enum = e || (Enum.new model, cursor)
                    if @enum.name == nil || @enum.name.empty?
                        # special case: there could be no name in enum typedef declaration
                        # in this case there is no name attached to enum which will make
                        # difficulties exporting it, just attach typedef name to enum
                        # name in this case
                        enum_without_name = true
                    end
                when :cursor_unexposed_attr
                    attribute = Bro.parse_attribute(cursor)
                    if attribute.is_a?(UnsupportedAttribute) && model.is_included?(self)
                        $stderr.puts "WARN: Typedef #{@name} at #{Bro.location_to_s(@location)} has unsupported attribute '#{attribute.source}'"
                    end
                    @attributes.push attribute
                else
                    raise "Unknown cursor kind #{cursor.kind} in typedef at #{Bro.location_to_s(@location)}"
                end
                next :continue
            end

            if enum_without_name
                # enum without name, attach name to it as well as visibility attributes 
                @enum.name = @name
                @enum.attributes += @attributes
            elsif @enum != nil && @enum.name == @name
                # copy attributes from typedef to enum
                @enum.attributes += @attributes
            end
        end

        def is_callback?
            !@parameters.empty?
        end

        def is_struct?
            @struct != nil || @is_structDef
        end

        def is_enum?
            @enum != nil
        end
    end

    class StructMember
        attr_accessor :name, :type
        def initialize(cursor: nil, name: nil, type: nil)
            if cursor.nil?
                @name = name
                @type = type
            else
                @name = cursor.spelling
                @type = cursor.type
            end
        end
    end

    class Struct < Entity
        attr_accessor :members, :children, :parent, :union, :type, :packed_align
        def initialize(model, cursor, parent = nil, union = false)
            super(model, cursor)
            @name = @name.gsub(/\s*\bconst\b\s*/, '')
            @name = @name.sub(/^(struct|union)\s*/, '')
            @name = "" if @name.start_with?('(unnamed at') || @name.start_with?('(anonymous at')

            @type = cursor.type
            @parent = parent
            @union = union

            # prepare to handle packer attribute 
            @packed_align = nil
            has_packed_attr = false
            align_attr_value = nil

            # parse members and anonymous structs/unions and put everyting into early_members
            # items will be sorted out after parsing
            early_members = []
            cursor.visit_children do |cursor, _parent|
                case cursor.kind
                when :cursor_unexposed_expr
                    # ignored
                when :cursor_visibility_attr
                    # ignored CXCursor_VisibilityAttr = 417,
                when :cursor_obj_c_boxable
                    # CXCursor_ObjCBoxable = 436
                    # ignored as no benefits of it
                    # typedef struct __attribute__((objc_boxable)) CGPoint CGPoint;
                when :cursor_aligned_attr
                    a = Bro.read_attribute(cursor)
                    if a.start_with?('aligned(') && a.end_with?(')')
                        align = a.sub('aligned(', '')[0..-2]
                        align = eval(align).to_i
                        align_attr_value = align
                    end
                when :cursor_field_decl
                    m = StructMember.new(cursor: cursor)
                    early_members.push m
                when :cursor_struct, :cursor_union
                    # add anonymous struct to be flatten, later it either be flatten or extracted as external
                    s = Struct.new model, cursor, self, cursor.kind == :cursor_union
                    if s.name.nil? || s.name.empty?
                        # inner anonymous struct, might be embedded, save for future processing
                        early_members.push s
                    else
                        # struct with tag, make global available
                        model.structs.push s
                    end

                when :cursor_unexposed_attr, :cursor_packed_attr, :cursor_annotate_attr
                    a = Bro.read_attribute(cursor)
                    if model.is_included?(self)
                        if a == "packed" || a == "__packed__"
                            has_packed_attr = true
                        elsif a.start_with?('aligned(') && a.end_with?(')')
                            align = a.sub('aligned(', '')[0..-2]
                            align = eval(align).to_i
                            align_attr_value = align
                        end
                    end
                else
                    raise "Unknown cursor kind #{cursor.kind} in struct at #{Bro.location_to_s(@location)}"
                end
                next :continue
            end

            # save packed attribute 
            @packed_align = (align_attr_value == nil ? 1 : align_attr_value) if has_packed_attr

            # process early members and replace anonymous structs/uniions
            @members = []
            @children = []
            # grandchildren - will contain children from child struct. just to keep own children on top of renaming list
            grandchildren = []
            idx = 1
            early_members.each_with_index do |e, i|
                if e.is_a?(Struct)
                    if i + 1 < early_members.length && early_members[i + 1].is_a?(StructMember) && Bro::location_to_id(early_members[i + 1].type.declaration.location) == e.id
                        # next item after this is stuct member that points to this anonymous struct/member
                        # just extract it to external struct (not subject for embedding)
                        @children.push e
                        model.structs.push e
                        # copy all children
                        grandchildren.concat(e.children)
                    elsif @union || e.union
                        # for union we can't expand structures into memebers
                        # as it is not supported at robovm end.
                        # logicaly we can't expand unions into structs.
                        # creating an entry for it, struct will be extracted
                        # into standalone entry
                        @members.push StructMember.new(name: "autoMember$#{idx}", type:e.type)
                        @children.push e
                        model.structs.push e
                    else
                        # anonymous struct
                        # copy all it members
                        @members.concat(e.members)
                        # copy all children
                        grandchildren.concat(e.children)
                    end
                else
                    @members.push e
                end
                idx += 1
            end

            # now attaching name for extracted structures
            @children.concat(grandchildren)
            if !@name.nil? && !@name.empty?
                idx = 1
                @children.each do |e|
                    e.name = "#{@name}$InnerStruct$#{idx}"
                    idx += 1
                end
            end
        end

        def types
            @members.map(&:type)
        end

        def is_opaque?
            @members.empty?
        end
    end

    class FunctionParameter
        attr_accessor :name, :type
        def initialize(cursor, def_name)
            @name = !cursor.spelling.empty? ? cursor.spelling : def_name
            @type = cursor.type
        end

        def name
            # escape names that slashes with Java keyworks
            case @name
            when 'native'
                '_native'
            when 'public'
                '_public'
            when 'private'
                '_private'
            when 'static'
                '_static'
            else
                @name
            end
        end
    end

    class Function < Entity
        attr_accessor :return_type, :parameters, :type, :inline_statement
        def initialize(model, cursor)
            super(model, cursor)
            @type = cursor.type
            @return_type = cursor.result_type
            @parameters = []
            param_count = 0
            @inline = cursor.extent.text.start_with?("static ") || cursor.extent.text.include?("static ")
            @variadic = cursor.variadic?
            cursor.visit_children do |cursor, _parent|
                case cursor.kind
                when :cursor_type_ref, :cursor_obj_c_class_ref, :cursor_obj_c_protocol_ref, :cursor_unexposed_expr, :cursor_ibaction_attr, 409, 410, :cursor_pure_attr
                    # Ignored
                when :cursor_const_attr
                    # Ignored, TODO -- might be useful
                when :cursor_obj_c_designated_initializer
                    # CXCursor_ObjCDesignatedInitializer = 434
                    # Ignored as not useful
                    # - (instancetype)init  __attribute__((objc_designated_initializer))
                when :cursor_visibility_attr
                    # CXCursor_VisibilityAttr = 417,
                    # ignored as doesn't provide useful information 
                    # extern __attribute__((visibility("default"))) const char * _Nonnull sel_getName(SEL _Nonnull sel)
                when :cursor_ns_returns_retained
                    # CXCursor_NSReturnsRetained = 420
                    # TODO -- might be useful
                    # FIXME: use it to attach or add warning about no retain marshaller 
                    #  __attribute__((__ns_returns_retained__))
                when :cursor_ns_consumes_self
                    # CXCursor_NSConsumesSelf = 423,
                    # ignored as doesn't provide useful information 
                    # - (nullable id)awakeAfterUsingCoder:(NSCoder *)coder __attribute__((ns_consumes_self)) __attribute__((ns_returns_retained));
                when :cursor_obj_c_returns_inner_pointer
                    # CXCursor_ObjCReturnsInnerPointer = 429
                    # ignored for now, as no common way to adopt it 
                    # - (nullable const char *)cStringUsingEncoding:(NSStringEncoding)encoding __attribute__((objc_returns_inner_pointer));
                when :cursor_obj_c_requires_super
                    # CXCursor_ObjCRequiresSuper = 430
                    # TODO: probably shell be added as JavaDoc that super call is requred (or annotation processor)
                    # - (void)updateConstraints __attribute__((availability(ios,introduced=6.0))) __attribute__((objc_requires_super));
                when :cursor_warn_unused_result_attr
                    # TODO: CXCursor_WarnUnusedResultAttr = 440
                when :cursor_parm_decl
                    @parameters.push FunctionParameter.new cursor, "p#{param_count}"
                    param_count += 1
                when :cursor_compound_stmt
                    @inline = true
                    @inline_statement = cursor.extent.text
                when :cursor_asm_label_attr, :cursor_unexposed_attr, :cursor_annotate_attr
                    attribute = Bro.parse_attribute(cursor)
                    if attribute.is_a?(UnsupportedAttribute) && model.is_included?(self)
                        $stderr.puts "WARN: Function #{@name} at #{Bro.location_to_s(@location)} has unsupported attribute '#{attribute.source}'"
                    end
                    @attributes.push attribute
                else
                    raise "Unknown cursor kind #{cursor.kind} in function #{@name} at #{Bro.location_to_s(@location)}"
                end
                next :continue
            end
        end

        def types
            [@return_type] + @parameters.map(&:type)
        end

        def is_variadic?
            @variadic
        end

        def is_inline?
            @inline
        end
    end

    class ObjCVar < Entity
        attr_accessor :type
        def initialize(model, cursor)
            super(model, cursor)
            @type = cursor.type
        end

        def types
            [@type]
        end
    end
    class ObjCInstanceVar < ObjCVar
    end
    class ObjCClassVar < ObjCVar
    end
    class ObjCMethod < Function
        attr_accessor :owner
        def initialize(model, cursor, owner)
            super(model, cursor)
            @owner = owner
        end
    end
    class ObjCInstanceMethod < ObjCMethod
        def initialize(model, cursor, owner)
            super(model, cursor, owner)
        end
        def full_name
            '-' + @name
        end
    end
    class ObjCClassMethod < ObjCMethod
        def initialize(model, cursor, owner)
            super(model, cursor, owner)

            s = Bro.read_source_range(cursor.extent)
            @class_property = !s.include?('+') # class properties are also recognized as class methods
        end

        def is_class_property?
            @class_property
        end

        def full_name
            '+' + @name
        end
    end

    class ObjCProperty < Entity
        attr_accessor :type, :owner, :getter, :setter, :attrs
        def initialize(model, cursor, owner)
            super(model, cursor)
            @type = cursor.type
            @owner = owner
            @getter = nil
            @setter = nil
            @source = Bro.read_source_range(cursor.extent)
            /@property\s*(\((?:[^)]+)\))/ =~ @source
            @attrs = !$1.nil? ? $1.strip.slice(1..-2).split(/,\s*/) : []
            @attrs = @attrs.each_with_object({}) do |o, h|
                pair = o.split(/\s*=\s*/)
                h[pair[0]] = pair.size > 1 ? pair[1] : true
                h
            end
            cursor.visit_children do |cursor, _parent|
                case cursor.kind
                when :cursor_type_ref, :cursor_parm_decl, :cursor_obj_c_class_ref, :cursor_obj_c_protocol_ref, :cursor_obj_c_instance_method_decl, :cursor_iboutlet_attr, :cursor_annotate_attr, :cursor_unexposed_expr
                    # Ignored
                when :cursor_visibility_attr
                when :cursor_obj_c_class_method_decl
                    # ignored CXCursor_VisibilityAttr = 417,
                when :cursor_obj_c_returns_inner_pointer
                    # ignored CXCursor_ObjCReturnsInnerPointer = 429
                    # @property (readonly) const char *objCType __attribute__((objc_returns_inner_pointer));
                when :cursor_obj_c_ns_object
                    # ignored CXCursor_ObjCNSObject = 426
                    # @property (nonatomic, readonly, retain, nullable) __attribute__((NSObject)) CGColorRef backgroundColor;
                when :cursor_unexposed_attr
                    attribute = Bro.parse_attribute(cursor)
                    if attribute.is_a?(UnsupportedAttribute) && model.is_included?(self)
                        $stderr.puts "WARN: ObjC property #{@name} at #{Bro.location_to_s(@location)} has unsupported attribute '#{attribute.source}'"
                    end
                    @attributes.push attribute
                else
                    raise "Unknown cursor kind #{cursor.kind} in ObjC property #{@name} at #{Bro.location_to_s(@location)}"
                end
                next :continue
            end
        end

        def getter_name
            @attrs['getter'] || @name
        end

        def setter_name
            base = @name[0, 1].upcase + @name[1..-1]
            @attrs['setter'] || "set#{base}:"
        end

        def is_static?
            @attrs['class']
        end

        def is_readonly?
            @setter.nil? && @attrs['readonly']
        end

        def types
            [@type]
        end

        def full_name
            is_static? ? ('+' + @name) : @name
        end
    end

    class ObjCMemberHost < Entity
        attr_accessor :instance_methods, :class_methods, :properties
        def initialize(model, cursor)
            super(model, cursor)
            @instance_methods = []
            @class_methods = []
            @properties = []
        end

        def resolve_property_accessors
            # Properties are also represented as instance methods in the AST. Remove any instance method
            # defined on the same position as a property and use the method name as getter/setter.
            @instance_methods -= @instance_methods.find_all do |m|
                p = @properties.find { |f| f.id == m.id || f.getter_name == m.name || f.setter_name == m.name }
                next unless p
                if m.name.end_with?(':')
                    p.setter = m
                else
                    p.getter = m
                end
                m
            end
        end

        def containsMember?(member)
            fn = member.full_name
            if member.is_a?(ObjCProperty)
                r = @properties.any? { |p| p.full_name == fn }
            elsif member.is_a?(ObjCClassMethod)
                r = @class_methods.any? { |p| p.full_name == fn }
            elsif member.is_a?(ObjCInstanceMethod)
                r = @instance_methods.any? { |p| p.full_name == fn }
            else
                false
            end
            r
        end
    end

    class ObjCTemplateParam < Entity
        attr_accessor :owner, :typedef_type
        def initialize(model, cursor, owner)
            super(model, cursor)
            @owner = owner
            @typedef_type = cursor.typedef_type
        end

        def java_name
            if !@java_name
                # check for configured first [
                conf = ((@model.get_class_conf(owner.name) || {})['template_parameters'] || {})[@name] || {}
                @java_name = if conf.is_a?(String) then conf else conf['name'] end
                if !@java_name
                    # replace known values 
                    if name == "ObjectType"
                        @java_name = "T"
                    elsif name == "KeyType"
                        @java_name = "K"
                    else 
                        @java_name = name
                    end
                end
            end
            @java_name
        end

        def extend_type
            if !@extend_type
                @extend_type = @model.resolve_type(@owner, @typedef_type)
            end
            @extend_type
        end

        def extend_java_type
            # try to pick from configuration first 
            conf = ((@model.get_class_conf(owner.name) || {})['template_parameters'] || {})[@name]
            t = nil
            t = conf['type'] if conf && conf.is_a?(Hash)
            t = " extends " + t if t && !t.empty?
            if !t 
                e = extend_type
                if e.is_a?(ObjCProtocol)
                    # if template arg type is a protocol -- need to extend it from NSObject as well, otherwise it 
                    # will not go to containers such as NSArray
                    t = "NSObject"
                    c = @model.get_protocol_conf(e.name)
                    t += " & " + e.java_name if c && !c['skip_implements'] && !c['skip_generics']
                elsif e.is_a?(ObjCId)
                    t = "NSObject"
                    t += " & " + e.java_name if !e.java_name.empty?
                else
                    t =  e.java_name
                end
                t = " extends " + t if t && !t.empty?
            end
            return t
        end
    end

    class ObjCClass < ObjCMemberHost
        attr_accessor :superclass, :protocols, :instance_vars, :class_vars, :template_params, :super_template_args
        def initialize(model, cursor)
            super(model, cursor)
            @superclass = nil
            @protocols = []
            @instance_vars = []
            @class_vars = []
            @template_params = []
            @super_template_args = nil
            if cursor.kind == :cursor_obj_c_class_ref
                @opaque = true
                return
            end

            generic_fix = false

            cursor.visit_children do |cursor, _parent|
                case cursor.kind
                when :cursor_unexposed_expr, :cursor_struct, :cursor_union, :cursor_type_ref
                    # ignored
                when :cursor_visibility_attr
                    # ignored CXCursor_VisibilityAttr = 417,
                    # ignored as doesn't provide useful information 
                    # extern __attribute__((visibility("default"))) @interface NSObject <NSObject> {
                when :cursor_obj_c_root_class
                    # CXCursor_ObjCRootClass = 431
                    # ignored as doesn't provide useful information 
                    # __attribute__((objc_root_class))  @interface NSObject <NSObject> {
                when :cursor_obj_c_exception
                    # ignored CXCursor_ObjCException = 425
                    # ignored as doesn't provide useful information 
                    # __attribute__((__objc_exception__)) @interface NSException : NSObject <NSCopying, NSSecureCoding>
                when :cursor_obj_c_subclassing_restricted
                    # TODO: check if useful
                when :cursor_obj_c_class_ref
                    @opaque = false if generic_fix
                    @opaque = @name == cursor.spelling unless generic_fix
                when :cursor_template_type_parameter
                    @template_params.push ObjCTemplateParam.new(model, cursor, self)
                when :cursor_obj_c_super_class_ref
                    generic_fix = true
                    @superclass = cursor.spelling
                when :cursor_obj_c_protocol_ref
                    @protocols.push(cursor.spelling)
                when :cursor_obj_c_instance_var_decl
                #          @instance_vars.push(ObjCInstanceVar.new(model, cursor))
                when :cursor_obj_c_class_var_decl
                #          @class_vars.push(ObjCClassVar.new(model, cursor))
                when :cursor_obj_c_instance_method_decl
                    method = ObjCInstanceMethod.new(model, cursor, self)
                    @instance_methods.push(method)
                when :cursor_obj_c_class_method_decl
                    @class_methods.push(ObjCClassMethod.new(model, cursor, self))
                when :cursor_obj_c_property_decl
                    @properties.push(ObjCProperty.new(model, cursor, self))
                when :cursor_unexposed_attr
                    attribute = Bro.parse_attribute(cursor)
                    if attribute.is_a?(UnsupportedAttribute) && model.is_included?(self)
                        $stderr.puts "WARN: ObjC class #{@name} at #{Bro.location_to_s(@location)} has unsupported attribute '#{attribute.source}'"
                    end
                    @attributes.push attribute
                else
                    raise "Unknown cursor kind #{cursor.kind} in ObjC class at #{Bro.location_to_s(@location)}"
                end
                next :continue
            end

            # pick up super class template argument
            # it is not available trough FFI so get declaration source code and fetch from 
            # there 
            # PS: but these could be also protocols, so will filter it out later 
            if !@opaque && @superclass
                t = cursor.extent.text.split(" ").join("")
                if t =~ /^@interface#{@name}(<.*?>)?:#{superclass}<(.*?)>/
                    @super_template_args = $2
                end
            end

            resolve_property_accessors
        end

        def types
            (@instance_vars.map(&:types) + @class_vars.map(&:types) + @instance_methods.map(&:types) + @class_methods.map(&:types) + @properties.map(&:types)).flatten
        end

        def is_opaque?
            @opaque
        end
    end

    class ObjCProtocol < ObjCMemberHost
        attr_accessor :protocols, :owner
        def initialize(model, cursor)
            super(model, cursor)
            @protocols = []
            @owner = nil
            if cursor.kind == :cursor_obj_c_protocol_ref
                @opaque = true
                return
            end

            @opaque = false
            cursor.visit_children do |cursor, _parent|
                case cursor.kind
                when :cursor_unexposed_expr, :cursor_visibility_attr
                    # ignored
                when :cursor_obj_c_explicit_protocol_impl
                    # ignored
                when :cursor_obj_c_protocol_ref
                    @opaque = @name == cursor.spelling
                    @protocols.push(cursor.spelling)
                when :cursor_obj_c_class_ref
                    @owner = cursor.spelling
                when :cursor_obj_c_instance_method_decl
                    @instance_methods.push(ObjCInstanceMethod.new(model, cursor, self))
                when :cursor_obj_c_class_method_decl
                    @class_methods.push(ObjCClassMethod.new(model, cursor, self))
                when :cursor_obj_c_property_decl
                    @properties.push(ObjCProperty.new(model, cursor, self))
                when :cursor_unexposed_attr
                    attribute = Bro.parse_attribute(cursor)
                    if attribute.is_a?(UnsupportedAttribute) && model.is_included?(self)
                        $stderr.puts "WARN: ObjC protocol #{@name} at #{Bro.location_to_s(@location)} has unsupported attribute '#{attribute.source}'"
                    end
                    @attributes.push attribute
                else
                    raise "Unknown cursor kind #{cursor.kind} in ObjC protocol #{@name} at #{Bro.location_to_s(@location)}"
                end
                next :continue
            end
            resolve_property_accessors
        end

        def is_informal?
            !!@owner
        end

        def types
            (@instance_methods.map(&:types) + @class_methods.map(&:types) + @properties.map(&:types)).flatten
        end

        def is_opaque?
            @opaque
        end

        def java_name
            name ? ((@model.get_protocol_conf(name) || {})['name'] || name) : ''
        end

        def is_class?
            name ? ((@model.get_protocol_conf(name) || {})['class'] || false) : false
        end
    end

    class ObjCCategory < ObjCMemberHost
        attr_accessor :owner, :protocols, :template_params
        def initialize(model, cursor)
            super(model, cursor)
            @protocols = []
            @template_params = []
            @owner = nil
            cursor.visit_children do |cursor, _parent|
                case cursor.kind
                when :cursor_unexposed_expr, :cursor_visibility_attr
                    # ignored
                when :cursor_obj_c_class_ref
                    @owner = cursor.spelling
                when :cursor_template_type_parameter
                    @template_params.push ObjCTemplateParam.new(model, cursor, self)
                when :cursor_obj_c_protocol_ref
                    @protocols.push(cursor.spelling)
                when :cursor_obj_c_instance_method_decl
                    @instance_methods.push(ObjCInstanceMethod.new(model, cursor, self))
                when :cursor_obj_c_class_method_decl
                    @class_methods.push(ObjCClassMethod.new(model, cursor, self))
                when :cursor_obj_c_property_decl
                    @properties.push(ObjCProperty.new(model, cursor, self))
                when :cursor_unexposed_attr
                    attribute = Bro.parse_attribute(cursor)
                    if attribute.is_a?(UnsupportedAttribute) && model.is_included?(self)
                        $stderr.puts "WARN: ObjC category #{@name} at #{Bro.location_to_s(@location)} has unsupported attribute '#{attribute.source}'"
                    end
                    @attributes.push attribute
                else
                    raise "Unknown cursor kind #{cursor.kind} in ObjC category at #{Bro.location_to_s(@location)}"
                end
                next :continue
            end
            resolve_property_accessors
        end

        def java_name
            # name ? ((@model.get_category_conf(name) || {})['name'] || name) : ''
            "#{@owner}Extensions"
        end

        def types
            (@instance_vars.map(&:types) + @class_vars.map(&:types) + @instance_methods.map(&:types) + @class_methods.map(&:types) + @properties.map(&:types)).flatten
        end
    end

    class GlobalValueDictionaryWrapper < Entity
        attr_accessor :name, :values
        def initialize(model, name, enum, first)
            super(model, nil)
            @name = name
            @enum = enum
            @type = first.type
            vconf = first.conf
            @java_type = vconf['type'] || @model.to_java_type(@model.resolve_type(self, @type))
            @mutable = vconf['mutable'].nil? ? true : vconf['mutable']
            @methods = vconf['methods']
            @generate_marshalers = vconf['marshalers'] || true
            @extends = vconf['dictionary_extends'] || vconf['extends'] || (is_foundation? ? 'NSDictionaryWrapper' : 'CFDictionaryWrapper')
            @constructor_visibility = vconf['constructor_visibility']
            @values = [first]
        end

        def is_foundation?
            !%w(CFType CFString CFNumber).include? @java_type
        end

        def is_mutable?
            @mutable
        end

        def generate_template_data(data)
            data['name'] = @name
            data['extends'] = @extends

            data['annotations'] = (data['annotations'] || []).push("@Library(#{$library})")

            if @generate_marshalers
                marshaler_lines = []
                append_marshalers(marshaler_lines)
                marshalers_s = marshaler_lines.flatten.join("\n    ")
                data['marshalers'] = "\n    #{marshalers_s}\n    "
            end

            constructor_lines = []
            append_constructors(constructor_lines)
            constructors_s = constructor_lines.flatten.join("\n    ")
            data['constructors'] = "\n    #{constructors_s}\n    "

            method_lines = []
            append_basic_methods(method_lines)
            append_convenience_methods(method_lines) unless @methods.nil?
            methods_s = method_lines.flatten.join("\n    ")
            data['methods'] = "\n    #{methods_s}\n    "

            if @enum.nil?
                key_lines = []
                append_key_class(key_lines)
                keys_s = key_lines.flatten.join("\n    ")
                data['keys'] = "\n    #{keys_s}\n    "
            end

            data
        end

        def append_marshalers(lines)
            dict_type = is_foundation? ? 'NSDictionary' : 'CFDictionary'
            base_type = is_foundation? ? 'NSObject' : 'CFType'

            lines << 'public static class Marshaler {'
            lines << '    @MarshalsPointer'
            lines << "    public static #{@name} toObject(Class<#{@name}> cls, long handle, long flags) {"
            lines << "        #{dict_type} o = (#{dict_type}) #{base_type}.Marshaler.toObject(#{dict_type}.class, handle, flags);"
            lines << '        if (o == null) {'
            lines << '            return null;'
            lines << '        }'
            lines << "        return new #{name}(o);"
            lines << '    }'
            lines << '    @MarshalsPointer'
            lines << "    public static long toNative(#{name} o, long flags) {"
            lines << '        if (o == null) {'
            lines << '            return 0L;'
            lines << '        }'
            lines << "        return #{base_type}.Marshaler.toNative(o.data, flags);"
            lines << '    }'
            lines << '}'

            array_type = is_foundation? ? "NSArray<#{dict_type}>" : 'CFArray'
            array_class = is_foundation? ? 'NSArray.class' : 'CFArray.class'

            lines << 'public static class AsListMarshaler {'
            lines << '    @MarshalsPointer'
            lines << "    public static List<#{@name}> toObject(Class<? extends #{base_type}> cls, long handle, long flags) {"
            lines << "        #{array_type} o = (#{array_type}) #{base_type}.Marshaler.toObject(#{array_class}, handle, flags);"
            lines << '        if (o == null) {'
            lines << '            return null;'
            lines << '        }'
            lines << "        List<#{@name}> list = new ArrayList<>();"
            lines << '        for (int i = 0; i < o.size(); i++) {'
            lines << "            list.add(new #{@name}(o.get(i)));" if is_foundation?
            lines << "            list.add(new #{@name}(o.get(i, CFDictionary.class)));" unless is_foundation?
            lines << '        }'
            lines << '        return list;'
            lines << '    }'
            lines << '    @MarshalsPointer'
            lines << "    public static long toNative(List<#{@name}> l, long flags) {"
            lines << '        if (l == null) {'
            lines << '            return 0L;'
            lines << '        }'
            lines << '        NSArray<NSDictionary> array = new NSMutableArray<>();' if is_foundation?
            lines << '        CFArray array = CFMutableArray.create();' unless is_foundation?
            lines << "        for (#{@name} i : l) {"
            lines << '            array.add(i.getDictionary());'
            lines << '        }'
            lines << "        return #{base_type}.Marshaler.toNative(array, flags);"
            lines << '    }'
            lines << '}'
        end

        def append_constructors(lines)
            dict_type = is_foundation? ? 'NSDictionary' : 'CFDictionary'

            constructor_visibility = @constructor_visibility.nil? ? '' : "#{@constructor_visibility} "

            lines << "#{constructor_visibility}#{@name}(#{dict_type} data) {"
            lines << '    super(data);'
            lines << '}'
            lines << "public #{@name}() {}" if is_mutable?
        end

        def append_basic_methods(lines)
            key_type = @enum ? @enum.name : @java_type
            key_value = @enum ? 'key.value()' : 'key'
            base_type = is_foundation? ? 'NSObject' : 'NativeObject'

            lines << "public boolean has(#{key_type} key) {"
            lines << "    return data.containsKey(#{key_value});"
            lines << '}'
            lines << "public NSObject get(#{key_type} key) {" if is_foundation?
            lines << "public <T extends NativeObject> T get(#{key_type} key, Class<T> type) {" unless is_foundation?
            lines << '    if (has(key)) {'
            lines << "        return data.get(#{key_value});" if is_foundation?
            lines << "        return data.get(#{key_value}, type);" unless is_foundation?
            lines << '    }'
            lines << '    return null;'
            lines << '}'
            if is_mutable?
                lines << "public #{@name} set(#{key_type} key, #{base_type} value) {"
                lines << "    data.put(#{key_value}, value);"
                lines << '    return this;'
                lines << '}'
            end
        end

        def append_convenience_methods(lines)
            lines << "\n"
            @values.find_all { |v| v.is_available? && !v.is_outdated? }.each do |v|
                vconf = v.conf
                java_name = v.java_name()

                method = @methods.detect { |m| java_name == m[0] || v.name == m[0] }
                next unless method
                mconf = method[1]
                name = mconf['name'] || method[0]
                param_name = mconf['param_name'] || name[0].downcase + name[1..-1]
                omit_prefix = mconf['omit_prefix'] || false
                type = mconf['type'] || 'boolean'

                getter = @model.getter_for_name(param_name, type, omit_prefix)

                default_value = mconf['default'] || @model.default_value_for_type(type)
                key_accessor = @enum ? "#{@enum.name}.#{java_name}" : "Keys.#{java_name}()"

                annotations = mconf['annotations'] && !mconf['annotations'].empty? ? mconf['annotations'].uniq.join(' ') : nil

                @model.push_availability(v, lines)
                lines << annotations.to_s if annotations
                lines << "public #{type} #{getter}() {"
                lines << "    if (has(#{key_accessor})) {"
                lines << convenience_getter_value(type, mconf['hint'], key_accessor)
                lines << '    }'
                lines << "    return #{default_value};"
                lines << '}'

                mutable = is_mutable?
                mutable = mconf['mutable'] unless mconf['mutable'].nil?

                next unless mutable
                setter = @model.setter_for_name(name, omit_prefix)

                convenience_setter = convenience_setter_value(type, mconf['hint'], param_name)
                if convenience_setter.respond_to?('each')
                    convenience_setter << "    set(#{key_accessor}, val);"
                    convenience_setter = convenience_setter.flatten.join("\n    ")
                else
                    convenience_setter = "    set(#{key_accessor}, #{convenience_setter});"
                end
                @model.push_availability(v, lines)
                lines << annotations.to_s if annotations
                lines << "public #{@name} #{setter}(#{type} #{param_name}) {"
                lines << convenience_setter
                lines << '    return this;'
                lines << '}'
                lines
            end
        end

        def convenience_getter_value(type, type_hint, key_accessor)
            s = []
            resolved_type = @model.resolve_type_by_name(type)

            type_no_generics = type.partition('<').first

            if type_hint
                hint_parts = type_hint.partition('<')
                type_generic_hint = hint_parts[2].partition('>').first
                type_hint = hint_parts.first
            end

            name = resolved_type ? resolved_type.name : type
            java_type = type

            if is_foundation?
                if resolved_type.is_a?(GlobalValueEnumeration) || type_hint == 'GlobalValueEnumeration'
                    java_type = resolved_type ? resolved_type.java_type : type_generic_hint
                    case java_type
                    when 'int', 'long', 'float', 'double'
                        s << "NSNumber val = (NSNumber) get(#{key_accessor});"
                        s << "return #{name}.valueOf(val.#{java_type}Value());"
                    else
                        s << "#{java_type} val = (#{java_type}) get(#{key_accessor});"
                        s << "return #{name}.valueOf(val);"
                    end
                elsif resolved_type.is_a?(GlobalValueDictionaryWrapper) || type_hint == 'GlobalValueDictionaryWrapper'
                    s << "NSDictionary val = (NSDictionary) get(#{key_accessor});"
                    s << "return new #{name}(val);"
                elsif resolved_type.is_a?(Enum)
                    s << "NSNumber val = (NSNumber) get(#{key_accessor});"
                    econf = @model.get_enum_conf(resolved_type.name)
                    s << if resolved_type.is_options? || econf['bits']
                             "return new #{resolved_type.name}(val.longValue());"
                         else
                             "return #{resolved_type.name}.valueOf(val.longValue());"
                         end
                elsif resolved_type == nil && type_hint == 'Enum'
                    # there is no direct reference for this type through includes, assume it is enum
                    s << "NSNumber val = (NSNumber) get(#{key_accessor});"
                    s << "return #{name}.valueOf(val.longValue());"
                elsif resolved_type.is_a?(Struct) || type_hint == 'Struct'
                    if type == 'CGRect' || type == 'CGSize' || type == 'CGAffineTransform' || type == 'NSRange' || type == 'UIEdgeInsets'
                        valueShort = type[2..-1]
                        valueShort[0] = valueShort[0].downcase
                        s << "NSValue val = (NSValue) get(#{key_accessor});"
                        s << "return val.#{valueShort}Value();"
                    elsif type_hint == 'Struct' || !resolved_type.is_opaque?
                        s << "NSData val = (NSData) get(#{key_accessor});"
                        s << "return val.getStructData(#{type}.class);"
                    else
                        s << "#{resolved_type.name} val = get(#{key_accessor}).as(#{resolved_type.name}.class);"
                        s << 'return val;'
                    end
                else
                    case type
                    when 'boolean', 'byte', 'short', 'char', 'int', 'long', 'float', 'double'
                        s << "NSNumber val = (NSNumber) get(#{key_accessor});"
                        s << "return val.#{type}Value();"
                    when 'String'
                        s << "NSString val = (NSString) get(#{key_accessor});"
                        s << 'return val.toString();'
                    when 'List<String>'
                        s << "NSArray<NSString> val = (NSArray<NSString>) get(#{key_accessor});"
                        s << 'return val.asStringList();'
                    when /^List<(.*)>$/

                        generic_type = @model.resolve_type_by_name($1.to_s)
                        if generic_type.is_a?(GlobalValueDictionaryWrapper)
                            s << "NSArray<?> val = (NSArray<?>) get(#{key_accessor});"
                            s << "List<#{$1}> list = new ArrayList<>();"
                            s << 'NSDictionary[] array = (NSDictionary[]) val.toArray(new NSDictionary[val.size()]);'
                            s << 'for (NSDictionary d : array) {'
                            s << "   list.add(new #{$1}(d));"
                            s << '}'
                            s << 'return list;'
                        else
                            s << "NSArray<#{$1}> val = (NSArray<#{$1}>) get(#{key_accessor});"
                            s << "return val;"
                        end
                    when 'Map<String, NSObject>'
                        s << "NSDictionary val = (NSDictionary) get(#{key_accessor});"
                        s << 'return val.asStringMap();'
                    when 'Map<String, String>'
                        s << "NSDictionary val = (NSDictionary) get(#{key_accessor});"
                        s << 'return val.asStringStringMap();'
                    else
                        s << "#{type} val = (#{type}) get(#{key_accessor});"
                        s << 'return val;'
                    end
                end
            else
                if resolved_type.is_a?(GlobalValueEnumeration) || type_hint == 'GlobalValueEnumeration'
                    java_type = resolved_type ? resolved_type.java_type : type_generic_hint
                    s << "#{java_type} val = get(#{key_accessor}, #{java_type}.class);"
                    s << "return #{name}.valueOf(val);"
                elsif resolved_type.is_a?(GlobalValueDictionaryWrapper) || type_hint == 'GlobalValueDictionaryWrapper'
                    s << "CFDictionary val = get(#{key_accessor}, CFDictionary.class);"
                    s << "return new #{name}(val);"
                elsif resolved_type.is_a?(Enum)
                    s << "CFNumber val = get(#{key_accessor}, CFNumber.class);"
                    econf = @model.get_enum_conf(resolved_type.name)
                    s << if resolved_type.is_options? || econf['bits']
                             "return new #{resolved_type.name}(val.longValue());"
                         else
                             "return #{resolved_type.name}.valueOf(val.longValue());"
                         end
                # ignore CMTime as its now being detected as Struct
                elsif resolved_type.is_a?(Struct) && type != 'CMTime' && !resolved_type.is_opaque? || type_hint == 'Struct'
                    s << "NSData val = get(#{key_accessor}, NSData.class);"
                    s << "return val.getStructData(#{type}.class);"
                else
                    case type
                    when 'boolean'
                        s << "CFBoolean val = get(#{key_accessor}, CFBoolean.class);"
                        s << 'return val.booleanValue();'
                    when 'byte', 'short', 'char', 'int', 'long', 'float', 'double'
                        s << "CFNumber val = get(#{key_accessor}, CFNumber.class);"
                        s << "return val.#{type}Value();"
                    when 'String'
                        s << "CFString val = get(#{key_accessor}, CFString.class);"
                        s << 'return val.toString();'
                    when 'List<String>'
                        s << "CFArray val = get(#{key_accessor}, CFArray.class);"
                        s << 'return val.asStringList();'
                    when /^List<(.*)>$/
                        s << "CFArray val = get(#{key_accessor}, CFArray.class);"

                        generic_type = @model.resolve_type_by_name($1.to_s)
                        if generic_type.is_a?(GlobalValueDictionaryWrapper)
                            s << "List<#{$1}> list = new ArrayList<>();"
                            s << 'CFDictionary[] array = val.toArray(CFDictionary.class);'
                            s << 'for (CFDictionary d : array) {'
                            s << "   list.add(new #{$1}(d));"
                            s << '}'
                            s << 'return list;'
                        else
                            s << "return val.toList(#{$1}.class);"
                              end
                    when 'Map<String, NSObject>'
                        s << "CFDictionary val = get(#{key_accessor}, CFDictionary.class);"
                        s << 'NSDictionary dict = val.as(NSDictionary.class);'
                        s << 'return dict.asStringMap();'
                    when 'Map<String, String>'
                        s << "CFDictionary val = get(#{key_accessor}, CFDictionary.class);"
                        s << 'return val.asStringStringMap();'
                    when 'CMTime'
                        s << "CFDictionary val = get(#{key_accessor}, CFDictionary.class);"
                        s << 'NSDictionary dict = val.as(NSDictionary.class);'
                        s << 'return CMTime.create(dict);'
                    else
                        s << "#{type} val = get(#{key_accessor}, #{type_no_generics}.class);"
                        s << 'return val;'
                    end
                end
            end
            '        ' + s.flatten.join("\n            ")
        end

        def convenience_setter_value(type, type_hint, param_name)
            s = nil
            resolved_type = @model.resolve_type_by_name(type)

            if type_hint
                hint_parts = type_hint.partition('<')
                type_generic_hint = hint_parts[2].partition('>').first
                type_hint = hint_parts.first
            end

            if is_foundation?
                if resolved_type.is_a?(GlobalValueEnumeration) || type_hint == 'GlobalValueEnumeration'
                    java_type = resolved_type ? resolved_type.java_type : type
                    case java_type
                    when 'int', 'long', 'float', 'double'
                        s = "NSNumber.valueOf(#{param_name}.value())"
                    else
                        s = "#{param_name}.value()"
                    end
                elsif resolved_type.is_a?(GlobalValueDictionaryWrapper) || type_hint == 'GlobalValueDictionaryWrapper'
                    s = "#{param_name}.getDictionary()"
                elsif resolved_type.is_a?(Enum) || type_hint == 'Enum'
                    s = "NSNumber.valueOf(#{param_name}.value())"
                elsif resolved_type.is_a?(Struct) || type_hint == 'Struct'
                    if type == 'CGRect' || type == 'CGSize' || type == 'CGAffineTransform' || type == 'NSRange' || type == 'UIEdgeInsets'
                        s = "NSValue.valueOf(#{param_name})"
                    elsif type_hint == 'Struct' || !resolved_type.is_opaque?
                        s = "new NSData(#{param_name})"
                    else
                        s = "#{param_name}.as(NSObject.class)"
                    end
                else
                    case type
                    when 'boolean', 'byte', 'short', 'char', 'int', 'long', 'float', 'double'
                        s = "NSNumber.valueOf(#{param_name})"
                    when 'String'
                        s = "new NSString(#{param_name})"
                    when 'List<String>'
                        s = "NSArray.fromStrings(#{param_name})"
                    when /List<(.*)>/
                        generic_type = @model.resolve_type_by_name($1.to_s)
                        if generic_type.is_a?(GlobalValueDictionaryWrapper)
                            s = []
                            s << '    NSArray<NSDictionary> val = new NSMutableArray<>();'
                            s << "    for (#{generic_type.name} e : #{param_name}) {"
                            s << '        val.add(e.getDictionary());'
                            s << '    }'
                        else
                            s = "new NSArray<>(#{param_name})"
                              end
                    when 'Map<String, NSObject>'
                        s = "NSDictionary.fromStringMap(#{param_name})"
                    when 'Map<String, String>'
                        s = "NSDictionary.fromStringStringMap(#{param_name})"
                    else
                        s = param_name
                    end
                end
            else
                if resolved_type.is_a?(GlobalValueEnumeration) || type_hint == 'GlobalValueEnumeration'
                    s = "#{param_name}.value()"
                elsif resolved_type.is_a?(GlobalValueDictionaryWrapper) || type_hint == 'GlobalValueDictionaryWrapper'
                    s = "#{param_name}.getDictionary()"
                elsif resolved_type.is_a?(Enum)
                    s = "CFNumber.valueOf(#{param_name}.value())"
                # ignore CMTime as its now being detected as Struct
                elsif resolved_type.is_a?(Struct) && type != 'CMTime' && !resolved_type.is_opaque?
                    s = "new NSData(#{param_name})"
                else
                    case type
                    when 'boolean'
                        s = "CFBoolean.valueOf(#{param_name})"
                    when 'byte', 'short', 'char', 'int', 'long', 'float', 'double'
                        s = "CFNumber.valueOf(#{param_name})"
                    when 'String'
                        s = "new CFString(#{param_name})"
                    when 'List<String>'
                        s = "CFArray.fromStrings(#{param_name})"
                    when /List<(.*)>/
                        generic_type = @model.resolve_type_by_name($1.to_s)
                        if generic_type.is_a?(GlobalValueDictionaryWrapper)
                            s = []
                            s << '    CFArray val = CFMutableArray.create();'
                            s << "    for (#{generic_type.name} e : #{param_name}) {"
                            s << '        val.add(e.getDictionary());'
                            s << '    }'
                        else
                            s = "CFArray.create(#{param_name})"
                              end
                    when 'Map<String, NSObject>'
                        s = "CFDictionary.fromStringMap(#{param_name})"
                    when 'Map<String, String>'
                        s = "CFDictionary.fromStringStringMap(#{param_name})"
                    when 'CMTime'
                        s = "#{param_name}.asDictionary(null).as(CFDictionary.class)"
                    else
                        s = param_name
                    end
                end
            end
            s
        end

        def append_key_class(lines)
            @values.sort_by { |v| v.since || 0.0 }

            lines << "@Library(#{$library})"
            lines << 'public static class Keys {'
            lines << '    static { Bro.bind(Keys.class); }'

            @values.find_all { |v| v.is_available? && !v.is_outdated? }.each do |v|
                vconf = v.conf

                indentation = '    '
                java_name = v.java_name()
                java_type = vconf['type'] || @model.to_java_type(@model.resolve_type(self, v.type, true))
                visibility = vconf['visibility'] || 'public'

                @model.push_availability(v, lines, indentation)
                if vconf.key?('dereference') && !vconf['dereference']
                    lines << "#{indentation}@GlobalValue(symbol=\"#{v.name}\", optional=true, dereference=false)"
                else
                    lines << "#{indentation}@GlobalValue(symbol=\"#{v.name}\", optional=true)"
                end
                lines << "#{indentation}#{visibility} static native #{java_type} #{java_name}();"
            end
             lines << '}'
        end

        private :append_marshalers, :append_constructors, :append_basic_methods, :append_convenience_methods, :append_key_class
    end

    class GlobalValueEnumeration < Entity
        attr_accessor :name, :type, :java_type, :values, :extends
        def initialize(model, name, first)
            super(model, nil)
            @name = name
            @type = first.type
            vconf = first.conf
            @java_type = vconf['type'] || model.to_java_type(model.resolve_type(self, @type, true))
            @extends = vconf['enum_extends'] || vconf['extends']
            @values = [first]
        end
    end

    class GlobalValue < Entity
        attr_accessor :type, :enum, :dictionary, :const, :java_name, :conf
        def initialize(model, cursor)
            super(model, cursor)
            @type = cursor.type

            typed_enum_conf = model.get_typed_enum_conf(@type)
            if typed_enum_conf && typed_enum_conf['transitive'] != true
                @conf = typed_enum_conf
                # picks configuration from typed_enum for global value as well to apply name transformation etc 
                c = model.get_conf_for_key(@name, @conf)
                @conf = @conf.merge(c) if c
            end
            @conf ||= model.get_value_conf(name)
            @enum = @conf ? @conf['enum'] : nil
            @dictionary = @conf ? @conf['dictionary'] : nil

            cursor.visit_children do |cursor, _parent|
                case cursor.kind
                when :cursor_type_ref, :cursor_integer_literal, :cursor_asm_label_attr, :cursor_obj_c_class_ref, :cursor_obj_c_protocol_ref, :cursor_unexposed_expr, :cursor_struct, :cursor_init_list_expr, :cursor_c_style_cast_expr, :cursor_floating_literal, :cursor_visibility_attr, :cursor_parm_decl
                    # Ignored
                when :cursor_visibility_attr
                    # TODO: ignored, might be useful
                when :cursor_unexposed_attr
                    attribute = Bro.parse_attribute(cursor)
                    if attribute.is_a?(UnsupportedAttribute) && model.is_included?(self)
                        $stderr.puts "WARN: Global value #{@name} at #{Bro.location_to_s(@location)} has unsupported attribute '#{attribute.source}'"
                    end
                    @attributes.push attribute
                else
                    raise "Unknown cursor kind #{cursor.kind} in global value #{@name} at #{Bro.location_to_s(@location)}"
                end
                next :continue
            end
        end

        def is_const?
            if @const
                @const
            elsif conf['readonly'] != nil
                # override with config 
                @const = conf['readonly']
            else
                # find out const status, check typedefs 
                t = @type
                if t.kind == 119 && t.declaration.kind == :cursor_typedef_decl
                    td_name = t.declaration.spelling
                    td = @model.typedefs.find { |e| e.name == td_name }
                    t = td.typedef_type if td
                end
                while t.kind == :type_typedef && !t.const?
                    td_name = type.spelling
                    td_name = td_name.gsub(/__strong\s*/, '')
                    td = @model.typedefs.find { |e| e.name == td_name }
                    break unless td
                    t = td.typedef_type
                end
                @const = t.spelling.match(/\bconst\b/) != nil
                if @const == false
                    # dkimitsa:
                    # there is a bug that const pointers are not reported as conststs
                    # for ex "CFStringRef  _Nonnull const", is being reported as
                    # "CFStringRef" which results in lot of setters for read only.
                    # also result_type is not populated
                    # fields. But result type can be obtained from cursor.completion
                    # and as workaround I will try this
                    if @cursor.completion != nil
                        ch = @cursor.completion.chunks.detect{|e| e[:kind] == :result_type}
                        ch = ch[:text] if ch != nil
                        @const = ch.match(/\bconst\b/) != nil if ch != nil
                    end
                end
            end
            @const
        end

        def java_name
            if @java_name
                @java_name
            else
                n = @conf['name']
                if n == nil
                    prefix = @conf["prefix"] || ""
                    suffix = @conf["suffix"] || ""
                    n = @name
                    n = n[prefix.size..-1] if n.start_with?(prefix)
                    n = n[0..(n.size - suffix.size - 1)] if n.end_with?(suffix)
                end
                n = "_#{n}" if n[0] >= '0' && n[0] <= '9'
                @java_name = n
                n
            end
        end
    end

    class ConstantValue < Entity
        attr_accessor :value, :type
        def initialize(model, cursor, value, type = nil)
            super(model, cursor)
            @name = cursor.spelling
            @value = value
            @type = type
            unless @type
                @type = if value.end_with?('L')
                            'long'
                        elsif value.end_with?('F') || value.end_with?('f')
                            'float'
                        elsif value =~ /^[-~]?((0x[0-9a-f]+)|([0-9]+))$/i
                            # auto promote to long
                            v = value.to_i()
                            @value = value + "L" if v > 2147483647 || v < (-2147483647-1)
                            @value.end_with?('L') ? 'long' : 'int'
                        else
                            'double'
                        end
            end

            cursor.visit_children do |cursor, _parent|
                case cursor.kind
                when :cursor_unexposed_attr
                    attribute = Bro.parse_attribute(cursor)
                    if attribute.is_a?(UnsupportedAttribute) && model.is_included?(self)
                        $stderr.puts "WARN: Const value #{@name} at #{Bro.location_to_s(@location)} has unsupported attribute '#{attribute.source}'"
                    end
                    @attributes.push attribute
                end
                next :continue
            end

            if @type == 'long' && @value == '9223372036854775807L'
                # We assume NSIntegerMax
                @value = 'Bro.IS_32BIT ? 0x7fffffffL : 0x7fffffffffffffffL'
            elsif @type == 'double' && @value == '1.7976931348623157e+308'
                @value = "Double.MAX_VALUE"
            end
        end
    end

    class EnumValue < Entity
        attr_accessor :name, :type, :enum, :raw_value
        def initialize(model, cursor, enum)
            super(model, cursor)
            @name = cursor.spelling
            @raw_value = cursor.enum_value
            @type = cursor.type

            @enum = enum
            @java_name = nil
            cursor.visit_children do |cursor, _parent|
                case cursor.kind
                when :cursor_unexposed_attr
                    attribute = Bro.parse_attribute(cursor)
                    if attribute.is_a?(UnsupportedAttribute) && model.is_included?(self)
                        $stderr.puts "WARN: Enum value #{@name} at #{Bro.location_to_s(@location)} has unsupported attribute '#{attribute.source}'"
                    end
                    @attributes.push attribute
                end
                next :continue
            end
        end

        def java_name
            if @java_name
                @java_name
            else
                n = @enum.enum_conf[@name] || @name

                match = @enum.enum_conf.find { |pattern, _value| $~ = @model.match_fully(pattern, @name) }
                if match && !$~.captures.empty?
                    def get_binding(g)
                        binding
                    end
                    b = get_binding($~.captures)
                    captures = $~.captures
                    v = match[1]
                    v = eval("\"#{v}\"", b) if v.is_a?(String) && v.match(/#\{/)
                    n = v
                end

                n = n[@enum.prefix.size..-1] if n.start_with?(@enum.prefix) && n != @enum.prefix
                n = n[0..(n.size - @enum.suffix.size - 1)] if n.end_with?(@enum.suffix) && n != @enum.suffix
                n = "_#{n}" if n[0] >= '0' && n[0] <= '9'
                @java_name = n
                n
            end
        end
    end

    class Enum < Entity
        attr_accessor :values, :type, :enum_type
        def initialize(model, cursor)
            super(model, cursor)
            @name = "" if @name.start_with?('enum (unnamed at')
            @values = []
            @type = cursor.type
            @enum_type = cursor.enum_type
            @enum_conf = nil
            cursor.visit_children do |cursor, _parent|
                case cursor.kind
                when 409
                    # Ignored
                when :cursor_visibility_attr
                    # CXCursor_VisibilityAttr = 417 
                when :cursor_flag_enum
                    # CXCursor_FlagEnum = 437
                    # typedef enum __attribute__((flag_enum,enum_extensibility(open)))
                when :cursor_enum_constant_decl
                    values.push EnumValue.new model, cursor, self
                when :cursor_unexposed_attr
                    attribute = Bro.parse_attribute(cursor)
                    if attribute.is_a?(UnsupportedAttribute) && model.is_included?(self)
                        $stderr.puts "WARN: enum #{@name} at #{Bro.location_to_s(@location)} has unsupported attribute #{Bro.read_attribute(cursor)}"
                    end
                    @attributes.push attribute
                else
                    raise "Unknown cursor kind #{cursor.kind} in enum at #{Bro.location_to_s(@location)}"
                end
                next :continue
            end
        end

        def java_enum_type
            if enum_conf['type']
                @model.resolve_type_by_name(enum_conf['type'])
            else
                # If this is a named enum (objc_fixed_enum) we take the enum int type from the first value
                @enum_type.kind == :type_enum ? @model.resolve_type(self, @values.first.type.canonical) : @model.resolve_type(self, @enum_type)
            end
        end

        def enum_conf
            unless @enum_conf
                @enum_conf = @model.conf_enums[name] || (@model.conf_enums.find { |k, v| k == name || v['first'] == values.first.name } || [{}, {}])[1]
            end
            @enum_conf
        end

        def suffix
            enum_conf['suffix'] || ''
        end

        def prefix
            if @prefix
                @prefix
            else
                name = self.name
                @prefix = enum_conf['prefix']
                return @prefix if @prefix
                if @values.size == 1
                    # calculate prefix from name
                    @prefix = @values[0].name.dup
                    if @prefix && name && prefix.start_with?(name + "_")
                        @prefix = name + "_"
                    elsif @prefix && name && prefix.start_with?(name)
                        @prefix = name
                    end
                elsif @values.size > 1
                    # Determine common prefix
                    @prefix = @values[0].name.dup
                    @values[1..-1].each do |p|
                        next unless p.enum == self
                        e = p.name
                        @prefix.slice!(e.size..-1) if e.size < @prefix.size # optimisation
                        @prefix.chop! while e.index(@prefix) != 0
                    end

                    # if calculated prefix is longer than name but name is
                    # common prefix, use name as prefix, otherwise it might cut
                    # elements name
                    if @prefix && name && prefix.start_with?(name + "_")
                        @prefix = name + "_"
                    elsif @prefix && name && prefix.start_with?(name)
                        @prefix = name
                    end
                end

                unless @prefix
                    $stderr.puts "WARN: Failed to determine prefix for enum #{name} with first #{@values[0].name} at #{Bro.location_to_s(@location)}"
                    @prefix = ''
                end
                @prefix
            end
        end
        alias super_name name
        def name
            n = nil
            n = ((@model.conf_enums.find { |_k, v| v['first'] == values.first.name }) || [nil]).first if values.length > 0
            unless n
                if @model.cfenums.include?(@id) || @model.cfoptions.include?(@id)
                    # This is a CF_ENUM or CF_OPTIONS. Find the typedef with the same location and use its name.
                    td = @model.typedefs.find { |e| e.id == @id }
                    n = td ? td.name : nil
                end
            end
            n || super_name
        end

        def is_options?
            @model.cfoptions.include?(@id)
        end

        def java_name
            n = enum_conf['name'] || self.name
            n
        end

        def merge_with
            enum_conf['merge_with']
        end

        # finding low level type of storage type as storage type can be specified as typedef type
        def raw_storage_type
            # shell be called once AST parse complete
            if !@raw_storage_type
                if enum_conf['type']
                    t = @model.resolve_type_by_name(enum_conf['type'])                   
                    t = @model.resolve_typedef(t.typedef_type) if t.is_a?(Typedef)  
                else
                    t = @model.resolve_typedef(@enum_type)
                end
                # in case of Builtin -- use its name as it was divided into separate entries to deliver
                # ability to pick information about signed/insigned
                @raw_storage_type = t.is_a?(Builtin) ? t.storage_type : t.java_name
            end

            @raw_storage_type
        end
    end

    class Model
        attr_accessor :conf, :typedefs, :functions, :objc_classes, :objc_protocols, :objc_categories, :global_values, :global_value_enums, :global_value_dictionaries, :constant_values, :structs, :enums, :cfenums,
                      :cfoptions, :conf_functions, :conf_values, :conf_constants, :conf_classes, :conf_protocols, :conf_categories, :conf_enums, :conf_typed_enums, :conf_generic_typedefs
        def initialize(conf)
            @conf = conf
            @conf_typedefs = @conf['typedefs'] || {}
            @conf_structdefs = @conf['structdefs'] || {}
            @conf_generic_typedefs = @conf['generic_typedefs'] || {}
            @conf_enums = @conf['enums'] || {}
            @conf_typed_enums = @conf['typed_enums'] || {}
            @conf_functions = @conf['functions'] || {}
            @conf_values = conf['values'] || {}
            @conf_constants = conf['constants'] || {}
            @conf_classes = @conf['classes'] || {}
            @conf_protocols = @conf['protocols'] || {}
            @conf_categories = @conf['categories'] || {}
            @typedefs = []
            @functions = []
            @global_values = []
            @global_value_enums = {}
            @global_value_dictionaries = {}
            @constant_values = []
            @structs = []
            @objc_classes = []
            @objc_protocols = []
            @objc_categories = []
            @enums = []
            @cfenums = [] # CF_ENUM(..., name) locations
            @cfoptions = [] # CF_OPTIONS(..., name) locations
            @type_cache = {}
        end

        def exclude_deprecated?
            b = @conf["exclude_deprecated"]
            b != nil && b
        end

        def min_usable_version
            (@conf["min_usable_version"] || $ios_version_min_usable).to_f
        end

        def default_config(name)
            @conf["default_#{name}_config"]
        end

        def inspect
            object_id
        end

        def resolve_type_by_name(name, generic = false, protocol_first: false )
            name = name.sub(/^(@ByVal|@Array.*)\s+/, '')
            orig_name = name
            # dkimitsa: if requested for generic search in separate configuration
            # this prevents NSString* to be converted into String in cases such
            # as NSArray<NSString*>
            if generic && @conf_generic_typedefs[name]
                name = @conf_generic_typedefs[name]
            else
                name = @conf_typedefs[name] || name
            end
            e = Bro.builtins_by_name(name)
            e ||= @global_value_enums[name]
            e ||= @global_value_dictionaries[name]
            e ||= @enums.find { |e| e.name == name }
            e ||= @structs.find { |e| e.name == name }
            if protocol_first
                e ||= @objc_protocols.find { |e| e.name == name }
                e ||= @objc_classes.find { |e| e.name == name }
            else 
                e ||= @objc_classes.find { |e| e.name == name }
                e ||= @objc_protocols.find { |e| e.name == name }
            end
            e ||= @typedefs.find { |e| e.name == name }
            e || (orig_name != name ? Builtin.new(name) : nil)
        end

        def build_type_cache_name(owner, type, generic)
            if owner && type.kind == :type_typedef && type.declaration.kind == :cursor_template_type_parameter && !@typedefs.find { |e| e.name == type.spelling }
                return owner.name + "." + type.spelling
            elsif owner && type.kind == 119 && type.declaration.kind == :cursor_template_type_parameter && !@typedefs.find { |e| e.name == type.declaration.spelling }
                return owner.name + "." + type.declaration.spelling
            elsif owner && type.spelling.include?("<")
                owner.name + "." + type.spelling
            elsif generic
                type.spelling + ".<generic>"
            else
                type.spelling
            end
        end

        # special version to resolve low level typedefs 
        # it differs from  resolve_type in way that it looks into c-definitions and ignores 
        # type matching by name (for example when typedef name matches enum generated from anonymous one)
        def resolve_typedef(type)
            name = type.spelling
            if @conf_typedefs[name] || @conf_classes[name] # if we have configuration override
                return resolve_type_by_name name
            elsif type.kind == :type_typedef || type.kind == 119 # CXType_Elaborated
                name = type.declaration.spelling if type.kind == 119 # CXType_Elaborated
                td = @typedefs.find { |e| e.name == name }
                if td
                    return resolve_typedef(td.typedef_type)
                end
            else
                e = Bro.builtins_by_type_kind(type.kind)
                return e if e
            end

            # check build-ins 
            return Bro.builtins_by_name(name)
        end

        def resolve_template_params(owner, generic_name, allow_dict_wrapper = false)
            valid_generics = false
            template_params = []
            template_params = owner.template_params if owner && (owner.is_a?(Bro::ObjCClass) || owner.is_a?(Bro::ObjCCategory))

            # work with generics, drop pointers if any
            generic_name = generic_name.tr('* ', '').sub(/__kindof/, '').sub(/id<(.*)>/, '\1')
            generics = generic_name.split(',')
            generic_types = []
            generics.each do |g|
                # special workaround for protocol extension to NSString, drop this
                g = 'NSString' if g.start_with?('NSString<') && g.end_with?('>')
                gtype = template_params.find {|n| n.name == g}
                if (gtype)
                    # its template param of this class 
                    valid_generics = true
                    generic_types.push(gtype)
                    next
                end

                # not template param, resolve by name
                # can't use Class in generic as ObjCClass is not inherited from NSObject as result
                # collections will not be able to work with it
                valid_generics = !(['Class', 'NSCopying'].include? g) && ['<', '>'].all? { |n| !g.include? n }
                break unless valid_generics

                if (g == 'id' || g == "NSObject")
                    generic_types.push(Builtin.new("?"))
                else
                    gtype = resolve_type_by_name(g, true)
                    if gtype.is_a?(Typedef)
                       # in case it is typedef -- expand it to bottom type or replace with typed enum types 
                        conf = @conf_typed_enums[gtype.name]
                        if conf 
                            # typed enum/dict case 
                            if conf["dictionary"]
                                gtype = resolve_type_by_name(conf["dictionary"])
                            else
                                gtype = resolve_type_by_name(conf["type"])
                            end 
                        else
                            gtype = resolve_type(owner, gtype.typedef_type, generic: true)
                        end
                    end
                    # expand value enum/dictionary to container class (as these are not subclass of NSObject and will fail to compile on containers)
                    gtype = resolve_type_by_name(gtype.java_type) if gtype.is_a?(GlobalValueEnumeration) 
                    gtype = resolve_type_by_name(gtype.java_type) if gtype.is_a?(GlobalValueDictionaryWrapper) && !allow_dict_wrapper
                    valid_generics = gtype.is_a?(ObjCClass) || gtype.is_a?(ObjCProtocol) || gtype.is_a?(Typedef) || gtype.is_a?(Builtin) || (allow_dict_wrapper && gtype.is_a?(GlobalValueDictionaryWrapper))
                    break unless valid_generics
                    generic_types.push(gtype)
                end
            end

            valid_generics ? generic_types : nil
        end

        def resolve_type(owner, type, allow_arrays = false, method = nil, generic: false, struct_member: false)
            cache_id = build_type_cache_name(owner, type, generic)
            t = @type_cache[cache_id]
            unless t
                t = resolve_type0(owner, type, allow_arrays, method, generic, struct_member)
                raise "Failed to resolve type '#{type.spelling}' with kind #{type.kind} defined at #{Bro.location_to_s(type.declaration.location)}" unless t
                if t.is_a?(Typedef) && t.is_callback?
                    # Callback.
                    t = Bro.builtins_by_name('FunctionPtr')
                end
                @type_cache[cache_id] = t if type.spelling != 'instancetype'
            end
            t
        end

        def resolve_type0(owner, type, allow_arrays, _method, _generic, _struct_member)
            return Bro.builtins_by_type_kind(:type_void) unless type
            name = type.spelling
            name = name.gsub(/\s*\bconst\b\s*/, '')
            name = name.gsub(/__strong\s*/, '')
            name = name.sub(/^(struct|union|enum)\s*/, '')

            gen_name = name !~ /^(id|NSObject)<.*>$/ ? name.gsub(/<.*>/, '').sub(/ *_(nonnull|nullable|null_unspecified) /i, '') : name

            if type.kind != :type_obj_c_object_pointer && @conf_typedefs[gen_name] # Try to lookup typedefs without generics
                resolve_type_by_name gen_name
            elsif @conf_typed_enums[name]
                if @conf_typed_enums[name]['class']
                    # if typed enum is just class with constant -- substitute type of it items instead of container 
                    n = @conf_typed_enums[name]['type']
                else 
                    n = @conf_typed_enums[name]['enum'] || @conf_typed_enums[name]['dictionary'] || @conf_typed_enums[name]['class']
                end
                resolve_type_by_name n
            elsif _generic && @conf_generic_typedefs[name]
                resolve_type_by_name name, true
            elsif @conf_typedefs[name]
                resolve_type_by_name name
            elsif @conf_structdefs[name]
                # create a typedef for this structure, mark it
                Typedef.new self, nil, @conf_structdefs[name]
            elsif type.kind == :type_obj_c_id
                resolve_type_by_name "NSObject"
            elsif type.kind == :type_function_proto
                Bro.builtins_by_name('FunctionPtr')
            elsif type.kind == :type_pointer
                e = nil
                if type.pointee.kind == :type_unexposed && name.match(/\(\*\)/)
                    # Callback. libclang does not expose info for callbacks.
                    e = Bro.builtins_by_name('FunctionPtr')
                elsif type.pointee.kind == :type_function_proto
                    e = Bro.builtins_by_name('FunctionPtr')
                elsif type.pointee.kind == :type_typedef && type.pointee.declaration.typedef_type.kind == :type_function_proto
                    e = Bro.builtins_by_name('FunctionPtr')
                elsif type.pointee.kind == :type_typedef && type.pointee.declaration.kind == :cursor_template_type_parameter
                    # pointer to template param, return as template type itself. E.g. '-(T*) foo'
                    e = resolve_type(owner, type.pointee)
                elsif type.pointee.kind == 119
                    if type.pointee.declaration.kind == :cursor_typedef_decl
                        td = @typedefs.find { |e| e.name == type.pointee.declaration.spelling }
                        if td
                            if td.typedef_type.kind == :cursor_template_type_parameter
                                e = td
                            elsif td.typedef_type.kind == :type_function_proto
                                e = Bro.builtins_by_name('FunctionPtr')
                            end
                        end
                    end
                end
                if e
                    e
                else
                    e = resolve_type(owner, type.pointee)
                    if e.is_a?(Enum) || e.is_a?(Typedef) && e.is_enum?
                        # Pointer to enum. Use an appropriate integer pointer (e.g. IntPtr)
                        enum = e.is_a?(Enum) ? e : e.enum
                        if type.pointee.canonical.kind == :type_enum
                            # Pointer to objc_fixed_enum
                            enum.java_enum_type.pointer
                        else
                            resolve_type(owner, type.pointee.canonical).pointer
                        end
                    else
                        e.pointer
                    end
                end
            elsif type.kind == :type_record
                e = @structs.find { |e| e.name == name }
                if e.nil?
                    # anonymous enums got here, try to find it using id
                    eid = Bro::location_to_id(type.declaration.location)
                    e = @structs.find { |e| e.id == eid}
                end
                e
            elsif type.kind == :type_obj_c_interface
                name = type.spelling
                # check typedefs for override first 
                if _generic && @conf_generic_typedefs[name]
                    name = @conf_generic_typedefs[name]
                else
                    name = @conf_typedefs[name] || name
                end
                e ||= @typedefs.find { |e| e.name == name }
                # then check for classes 
                e ||= @objc_classes.find { |e| e.name == name }
                e
            elsif type.kind == :type_obj_c_object_pointer || type.kind == 161 # CXType_ObjCObject = 161 # consider point to obj and objc object same
                name = type.pointee.spelling
                if type.pointee.kind == :type_typedef
                    # look up for case typedef NSObject MYObject;
                    td = @typedefs.find { |e| e.name == name }
                    name = td.typedef_type.spelling if td
                elsif type.pointee.kind == 119 && type.pointee.declaration.kind == :cursor_typedef_decl
                    # look up for case typedef NSObject MYObject;
                    td = @typedefs.find { |e| e.name == type.pointee.spelling }
                    name = td.typedef_type.spelling if td
                end
                name = name.gsub(/__kindof\s*/, '')
                name = name.gsub(/\s*\bconst\b\s*/, '')

                if name =~ /^(id|NSObject)<(.*)>$/
                    # Protocols
                    names = $2.split(/\s*,/)
                    types = names.map { |e| resolve_type_by_name(e, protocol_first: true) }
                    if types.find_all(&:!).empty?
                        if types.size == 1
                            if types[0].name == "NSObject"
                                # do not return NSObject protocol as it is empty in RoboVM implementation and
                                # this might affect marshaller and retain/release cycles
                                resolve_type_by_name('NSObject')
                            else
                                types[0]
                            end
                        else
                            ObjCId.new(self, types)
                        end
                    end
                elsif name =~ /^(Class)<(.*)>$/
                    resolve_type_by_name('ObjCClass')
                elsif name =~ /(.*?)<(.*)>/ # Generic type
                    type_name = $1
                    generic_name = $2.tr('* ', '').sub(/__kindof/, '').sub(/id<(.*)>/, '\1')

                    generic_types = nil
                    e = resolve_type_by_name(type_name)
                    if e && e.pointer
                        java_type = nil
                        # dkimitsa:
                        # special case: replacing NSDictionary<NS_TYPED_ENUM, ? > to
                        # typed_enum#dict if such is found
                        if type_name == "NSDictionary" 
                            gt = resolve_template_params(owner, generic_name, true)
                            if gt && gt.length == 2 && gt[1].java_name == "?" && gt[0].is_a?(GlobalValueDictionaryWrapper)
                                # replace with dictionary wrapper 
                                return gt[0]
                            end
                        end
        
                        # proceed common generic way 
                        generic_types = resolve_template_params(owner, generic_name)
                    end

                    if generic_types
                        [e] + generic_types
                    else
                        if @conf_typedefs[gen_name]
                            resolve_type_by_name gen_name
                        else
                            e && e.pointer
                        end
                    end
                else
                    e = resolve_type_by_name(name)
                    e && e.pointer
                end
            elsif type.kind == :type_enum
                @enums.find { |e| e.name == name }
            elsif type.kind == :type_incomplete_array || type.kind == :type_unexposed && name.end_with?('[]')
                # type is an unbounded array (void *[]). libclang does not expose info on such types.
                # Replace all [] with *
                name = name.gsub(/\[\]/, '*')
                # remove all _Nullable
                name = name.gsub(/[\s]*_Nullable[\s]*/, '')
                name = name.sub(/^(id|NSObject)(<.*>)?\s*/, 'NSObject *')
                base = name.sub(/^(.*?)[\s]*[*]+/, '\1')
                e = case base
                    when /^(unsigned )?char$/ then resolve_type_by_name('byte')
                    when /^long$/ then resolve_type_by_name('MachineSInt')
                    when /^unsigned long$/ then resolve_type_by_name('MachineUInt')
                    else resolve_type_by_name(base)
                end
                if e
                    cnt = name.scan(/\*/).count
                    if _struct_member && cnt == 1
                        # resolving for struct member, return as zero length array, struct related code will replace with pointer
                        e =  Array.new(e, [0])
                    else 
                        # Wrap in Pointer as many times as there are *s in name
                        e = (1..cnt).inject(e) { |t, _i| t.pointer }
                    end
                end
                e
            elsif type.kind == :type_unexposed
                e = @structs.find { |e| e.name == name }
                e ||= @enums.find { |e| e.name == name || e.super_name == name }
                unless e
                    if name.end_with?('[]')
                        # type is an unbounded array (void *[]). libclang does not expose info on such types.
                        # Replace all [] with *
                        name = name.gsub(/\[\]/, '*')
                        name = name.sub(/^(id|NSObject)(<.*>)?\s*/, 'NSObject *')
                        base = name.sub(/^([^\s*]+).*/, '\1')
                        e = case base
                            when /^(unsigned )?char$/ then resolve_type_by_name('byte')
                            when /^long$/ then resolve_type_by_name('MachineSInt')
                            when /^unsigned long$/ then resolve_type_by_name('MachineUInt')
                            else resolve_type_by_name(base)
                        end
                        if e
                            # Wrap in Pointer as many times as there are *s in name
                            e = (1..name.scan(/\*/).count).inject(e) { |t, _i| t.pointer }
                        end
                    elsif name =~ /\(/
                        # Callback. libclang does not expose info for callbacks.
                        e = Bro.builtins_by_name('FunctionPtr')
                    end
                end
                e
            elsif type.kind == :type_typedef
                if name == 'instancetype' && owner
                    e = owner
                    if owner.is_a?(Bro::ObjCCategory)
                        e = resolve_type_by_name(owner.owner)
                    end
                    if e.is_a?(Bro::ObjCClass) && !e.template_params.empty?
                        # owner has generic parameter type, turn into generic
                        e = [e] + e.template_params
                    end
                    e
                elsif type.declaration.kind == :cursor_template_type_parameter
                    # Find template parameter in objc class 
                    e = nil
                    if owner && (owner.is_a?(Bro::ObjCClass) || owner.is_a?(Bro::ObjCCategory))
                        e = owner.template_params.find { |e| e.name == name }
                    end
                    e
                else
                    td = @typedefs.find { |e| e.name == name }
                    if !td
                        if type.declaration.kind == :cursor_template_type_parameter
                            resolve_type(owner, type.declaration.underlying_type)
                        else
                            # Check builtins for builtin typedefs like va_list
                            Bro.builtins_by_name(name)
                        end
                    else
                        if td.typedef_type.kind == :type_block_pointer
                            resolve_type(owner, td.typedef_type)
                        elsif td.is_callback? || td.is_struct?
                            td
                        elsif get_class_conf(td.name)
                            td
                        else
                            e = @enums.find { |e| e.name == name || e.id == td.id}
                            e || resolve_type(owner, td.typedef_type)
                        end
                    end
                end
            elsif type.kind == :type_constant_array
                dimensions = []
                base_type = type
                while base_type.kind == :type_constant_array
                    dimensions.push base_type.array_size
                    base_type = base_type.element_type
                end
                if allow_arrays
                    Array.new(resolve_type(owner, base_type), dimensions)
                else
                    # Marshal as pointer
                    (1..dimensions.size).inject(resolve_type(owner, base_type)) { |t, _i| t.pointer }
                end
            elsif type.kind == :type_block_pointer
                begin
                    ret_type = resolve_type(owner, type.pointee.result_type)
                    param_types = (0..type.pointee.num_arg_types-1).map { |idx| resolve_type(owner, type.pointee.arg_type(idx), generic: true)}
                    Block.new(self, ret_type, param_types)
                rescue => e
                    $stderr.puts "WARN: Unknown block type #{name}. Using ObjCBlock. Failed to convert due: #{e}"
                    Bro.builtins_by_type_kind(type.kind)
                end
            elsif type.kind == 119 # CXType_Elaborated
                e = nil
                name = type.declaration.spelling

                if type.declaration.kind == :cursor_struct || type.declaration.kind == :cursor_union
                    eid = Bro::location_to_id(type.declaration.location)
                    e = @structs.find { |e| e.name == name || e.id == eid}
                elsif type.declaration.kind == :cursor_enum_decl
                    name = type.declaration.spelling
                    eid = Bro::location_to_id(type.declaration.location)
                    e = @enums.find { |e| e.name == name || e.id == eid}
                elsif type.declaration.kind == :cursor_template_type_parameter
                    # Find template parameter in objc class
                    if owner && (owner.is_a?(Bro::ObjCClass) || owner.is_a?(Bro::ObjCCategory))
                        e = owner.template_params.find { |e| e.name == name }
                    end
                elsif type.declaration.kind == :cursor_typedef_decl
                    td = @typedefs.find { |e| e.name == name }
                    if td
                        if td.typedef_type.kind == :type_block_pointer
                            e = resolve_type(owner, td.typedef_type)
                        elsif td.is_callback? || td.is_struct?
                            e = td
                        elsif get_class_conf(td.name)
                            e = td
                        else
                            e = @enums.find { |e| e.name == name || e.id == td.id}
                            e = e || resolve_type(owner, td.typedef_type)
                        end
                    end
                end
                if !e
                    $stderr.puts "WARN: Unknown elaborated type #{name}"
                    if name.start_with?('class ')
                        name = name.sub('class ', '')
                    end
                    e = resolve_type_by_name name
                end
                e
            else
                # Could still be an enum
                e = @enums.find { |e| e.name == name }
                # If not check builtins
                e ||= Bro.builtins_by_type_kind(type.kind)
                # And finally typedefs
                e ||= @typedefs.find { |e| e.name == name }
                e
            end
        end

        def match_fully(pattern, s)
            pattern = pattern[1..-1] if pattern.start_with?('^')
            pattern = pattern.chop if pattern.end_with?('$')
            pattern = "^#{pattern}$"
            s.match(pattern)
        end

        def find_conf_matching(name, conf)
            match = conf.find { |pattern, _value| $~ = match_fully(pattern.start_with?('+') ? "\\#{pattern}" : pattern, name) }
            if !match
                nil
            elsif !$~.captures.empty?
                def get_binding(g)
                    binding
                end
                b = get_binding($~.captures)
                # Perform substitution on children
                captures = $~.captures
                h = {}
                match[1].keys.each do |key|
                    v = match[1][key]
                    v = eval("\"#{v}\"", b) if v.is_a?(String) && v.match(/#\{/)
                    h[key] = v
                end
                h
            else
                match[1]
            end
        end

        def get_conf_for_key(name, conf)
            conf[name] || find_conf_matching(name, conf)
        end

        def get_class_conf(name)
            get_conf_for_key(name, @conf_classes)
        end

        def get_protocol_conf(name)
            get_conf_for_key(name, @conf_protocols)
        end

        def get_category_conf(name)
            get_conf_for_key(name, @conf_categories)
        end

        def get_function_conf(name)
            get_conf_for_key(name, @conf_functions)
        end

        def get_value_conf(name)
            get_conf_for_key(name, @conf_values)
        end

        def get_constant_conf(name)
            get_conf_for_key(name, @conf_constants)
        end

        def get_enum_conf(name)
            get_conf_for_key(name, @conf_enums)
        end

        def get_typed_enum_conf(type)
            name = type.spelling
            name = name.gsub(/\s*\bconst\b\s*/, '')
            name = name.gsub(/__strong\s*/, '')
            name = name.sub(/^(struct|union|enum)\s*/, '')
            name = name.sub(/ *_(nonnull|nullable|null_unspecified) /i, '')
            e = get_conf_for_key(name, @conf_typed_enums)
            e if e != nil && !e['exclude']
        end

        def is_byval_type?(type)
            type.is_a?(Struct) || type.is_a?(Typedef) && (type.is_struct? || type.typedef_type.kind == :type_record)
        end

        def to_java_generic_type(type)
            notAcceptingProto = [
                "NSArray", "NSMutableArray", "NSSet", "NSMutableSet", "NSOrderedSet", "NSDictionary",
                "NSMutableDictionary", "NSEnumerator"
            ]
            ownerName = type[0].java_name

            # do not declare protocol extension as generic -- check if there are template_params in owner
            template_params = nil
            template_params = type[0].template_params if (type[0].is_a?(Bro::ObjCClass))
            if template_params == nil || template_params.length == 0
                ownerName
            elsif notAcceptingProto.include?(ownerName)
                # protocols are not allowed in NS containers yet
                "#{ownerName}<" + type[1..-1].map{ |e|
                    e.is_a?(ObjCProtocol) && !e.is_class? ? '?' : e.java_name
                }.join(", ") + ">"
            else
                # generic
                "#{ownerName}<" + type[1..-1].map{ |e| e.java_name}.join(", ") + ">"
            end
        end

        def to_java_type(type)
            if is_byval_type?(type)
                "@ByVal #{type.java_name}"
            elsif type.is_a?(Array)
                "@Array({#{type.dimensions.join(', ')}}) #{type.java_name}"
            elsif type.respond_to?('each') # Generic type
                to_java_generic_type(type)
            else
                type.java_name
            end
        end

        def to_wrapper_java_type(type)
        	# same as above but used for wrapper parameter definition thues not requires Bro annotation
            if type.respond_to?('each') # Generic type
                to_java_generic_type(type)
            else
                type.java_name
            end
        end

        def is_included?(entity)
            framework = conf['framework']
            internal_frameworks = conf['internal_frameworks']
            path_match = conf['path_match']

            # checking library here as well as AudioUnit currently in AudioToolBox which cause all API is not included
            if path_match && entity.location.file.match(path_match)
                true
            elsif framework && entity.framework == framework || internal_frameworks && internal_frameworks.include?(entity.framework)
                true
            else
                false
            end
        end

        def is_location_included?(location)
            framework = conf['framework']
            internal_frameworks = conf['internal_frameworks']
            path_match = conf['path_match']

            # checking library here as well as AudioUnit currently in AudioToolBox which cause all API is not included
            if path_match && location.file.match(path_match)
                true
            elsif framework 
                location_framework = location.file.to_s.split(File::SEPARATOR).reverse.find_all { |e| e.match(/^.*\.(framework|lib)$/) }.map { |e| e.sub(/(.*)\.(framework|lib)/, '\1') }.first
                location_framework == framework || internal_frameworks && internal_frameworks.include?(location_framework)
            else
                false
            end
        end

        def getter_for_name(name, type, omit_prefix)
            base = omit_prefix ? name[0..-1] : name[0, 1].upcase + name[1..-1]
            getter = name

            unless omit_prefix
                if type == 'boolean'
                    case name.to_s
                    when /^is\p{Lu}/, /^has\p{Lu}/, /^can\p{Lu}/, /^should/, /^adjusts/, /^allows/, /^always/, /^animates/, /^appends/,
                      /^applies/, /^apportions/, /^are/, /^autoenables/, /^automatically/, /^autoresizes/,
                      /^autoreverses/, /^bounces/, /^cancels/, /^casts/, /^checks/, /^clears/, /^clips/, /^collapses/, /^contains/, /^creates/,
                      /^defers/, /^defines/, /^delays/, /^depends/, /^did/, /^dims/, /^disables/, /^disconnects/, /^displays/,
                      /^does/, /^draws/, /^embeds/, /^enables/, /^enumerates/, /^evicts/, /^expects/, /^fixes/, /^fills/, /^flattens/, /^flips/, /^generates/, /^groups/,
                      /^hides/, /^ignores/, /^includes/, /^infers/, /^installs/, /^invalidates/, /^keeps/, /^locks/, /^marks/, /^masks/, /^merges/, /^migrates/, /^needs/,
                      /^normalizes/, /^notifies/, /^obscures/, /^opens/, /^overrides/, /^pauses/, /^performs/, /^prefers/, /^presents/, /^preserves/, /^propagates/,
                      /^provides/, /^reads/, /^receives/, /^recognizes/, /^remembers/, /^removes/, /^requests/, /^requires/, /^resets/, /^resumes/, /^returns/, /^reverses/,
                      /^scrolls/, /^searches/, /^sends/, /^shows/, /^simulates/, /^sorts/, /^supports/, /^suppresses/, /^tracks/, /^translates/, /^uses/, /^wants/, /^writes/,
                      /^preloads/, /^may\p{Lu}/
                        getter = name
                    else
                        getter = "is#{base}"
                    end
                else
                    getter = "get#{base}"
                end
            end
            getter
        end

        def setter_for_name(name, omit_prefix)
            base = omit_prefix ? name[0..-1] : name[0, 1].upcase + name[1..-1]
            omit_prefix ? base : "set#{base}"
        end

        def default_value_for_type(type)
            default = 'null'
            case type
            when 'boolean'
                default = false
            when 'byte', 'short', 'char', 'int', 'long', 'float', 'double'
                default = 0
            end
            default
        end

        def push_availability(entity, lines = [], indentation = '', annotation_lines: nil)
            since = entity.since
            since = nil if since && since <= $ios_version_min_usable.to_f
            deprecated = entity.deprecated
            deprecated = -1 if deprecated && deprecated > $ios_version.to_f # in case of API_TO_BE_DEPRECATED
            reason = entity.reason
            if since || deprecated && (deprecated > 0 || reason)
                lines.push("#{indentation}/**")
                lines.push("#{indentation} * @since Available in iOS #{since} and later.") if since
                lines.push("#{indentation} * @deprecated Deprecated in iOS #{deprecated}.") if deprecated && deprecated > 0 && !reason
                lines.push("#{indentation} * @deprecated Deprecated in iOS #{deprecated}. #{reason}") if deprecated && deprecated > 0 && reason
                lines.push("#{indentation} * @deprecated #{reason}") if deprecated && deprecated < 0 && reason
                lines.push("#{indentation} */")
            end
            (annotation_lines != nil ? annotation_lines : lines).push("#{indentation}@Deprecated") if deprecated
            lines
        end

        def extract_static_constant_value(cursor)
            value = nil
            cursor.visit_children do |cursor, _parent|
                case cursor.kind
                when :cursor_obj_c_string_literal
                    value = cursor.extent.text
                    # workaround if receive it with @ 
                    value = value[1..-1] if value.start_with?('@"') && value.end_with?('"')
                when :cursor_integer_literal
                    value = cursor.extent.text
                    # workaround if ends with L
                    value = value[0..-2] if value.end_with?('L')
                when :cursor_unexposed_expr, :cursor_unary_expr
                    value = cursor.extent.text
                    value = value[1..-1] if value.start_with?('@"') && value.end_with?('"')
                when :cursor_binary_operator
                    value = cursor.extent.text
                end

                next :continue
            end

            return value
        end

        def process(cursor)
            cursor.visit_children do |cursor, _parent|
                case cursor.kind
                when :cursor_typedef_decl
                    @typedefs.push Typedef.new self, cursor
                    next :continue
                when :cursor_struct, :cursor_union
                    if cursor.spelling
                        # Ignore anonymous top-level records. They have to be accessed through a typedef
                        @structs.push Struct.new self, cursor, nil, cursor.kind == :cursor_union
                    end
                    next :continue
                when :cursor_enum_decl
                    e = Enum.new self, cursor
                    @enums.push(e) unless e.values.empty?
                    next :continue
                when :cursor_macro_definition
                    name = cursor.spelling.to_s
                    src = Bro.read_source_range(cursor.extent)
                    if src != '?'
                        src = src[name.length..-1]
                        src.strip!
                        src = src[1..-2] while src.start_with?('(') && src.end_with?(')')
                        src = src.sub(/^\((long long|long|int)\)/, '')
                        if src =~ /^(([-+.0-9Ee]+[fF]?)|(~?0x[0-9a-fA-F]+[UL]*)|(~?[0-9]+[UL]*))$/i
                            # include macros that look like integer or floating point values for now
                            value = $1
                            value = value.sub(/^((0x)?.*)U$/i, '\1')
                            value = value.sub(/^((0x)?.*)UL$/i, '\1')
                            value = value.sub(/^((0x)?.*)ULL$/i, '\1L')
                            value = value.sub(/^((0x)?.*)LL$/i, '\1L')
                            @constant_values.push ConstantValue.new self, cursor, value
                        elsif src =~ /^[@]?(".*")$/i
                            # try to pick up strings, could be broken in comlex cases
                            value = $1
                            @constant_values.push ConstantValue.new self, cursor, value, String
                        else
                            v = @constant_values.find { |e| e.name == src }
                            if v
                                @constant_values.push ConstantValue.new self, cursor, v.value, v.type
                            end
                        end
                    end
                    next :continue
                when :cursor_macro_expansion
                    if cursor.spelling.to_s == 'CF_ENUM' || cursor.spelling.to_s == 'NS_ENUM'
                        @cfenums.push Bro.location_to_id(cursor.location)
                    elsif cursor.spelling.to_s == 'CF_OPTIONS' || cursor.spelling.to_s == 'NS_OPTIONS'
                        @cfoptions.push Bro.location_to_id(cursor.location)
                    end
                    next :continue
                when :cursor_function
                    @functions.push Function.new self, cursor
                    next :continue
                when :cursor_variable
                    # check if variable definition starts with static in this case it can't be
                    # global value and should be converted to constant if possible
                    src = Bro.read_source_range(cursor.extent)
                    if src == '?' || !(src.strip =~ /^static/)
                        @global_values.push GlobalValue.new self, cursor
                    else
                        # static variable, get value
                        value = extract_static_constant_value(cursor)
                        value_orig = value
                        if value
                            const=nil
                            begin
                                # FIXME: there is a chance that value under eval will match ruby api module var which
                                # will cause side effects
                                value = eval(value)
                                if value.class == String
                                    const = ConstantValue.new self, cursor, '"' + value + '"', String
                                else
                                    const = ConstantValue.new self, cursor, value.to_s
                                end
                            rescue Exception => e
                                # check if is a reference to a constant
                                value = @constant_values.find { |e| e.name == value }
                                if value
                                    const = ConstantValue.new self, cursor, value.value, value.type
                                end
                            end
                            if const
                                @constant_values.push const
                            else
                                $stderr.puts "WARN: Failed to turning the global value #{cursor.spelling} into constants (eval failed), value #{value_orig}" if is_location_included?(cursor.location)
                            end
                        else
                            $stderr.puts "WARN: Ignoring static global value #{cursor.spelling} without value at #{Bro.location_to_s(cursor.location)}" if is_location_included?(cursor.location)
                        end
                    end
                    next :continue
                when :cursor_obj_c_interface_decl
                    @objc_classes.push ObjCClass.new self, cursor
                    next :continue
                when :cursor_obj_c_class_ref
                    @objc_classes.push ObjCClass.new self, cursor
                    next :continue
                when :cursor_obj_c_protocol_decl
                    @objc_protocols.push ObjCProtocol.new self, cursor
                    next :continue
                when :cursor_obj_c_protocol_ref
                    @objc_protocols.push ObjCProtocol.new self, cursor
                    next :continue
                when :cursor_obj_c_category_decl
                    cat = ObjCCategory.new self, cursor
                    c = get_category_conf("#{cat.name}@#{cat.owner}")
                    c = get_category_conf(cat.name) unless c
                    if c && c['protocol']
                        @objc_protocols.push ObjCProtocol.new self, cursor
                    else
                        @objc_categories.push cat
                    end
                    next :continue
                else
                    next :recurse
                end
            end

            # Sort structs so that opaque structs come last. If a struct has a definition it should be used and not the forward declaration.
            @structs = @structs.sort { |a, b| (a.is_opaque? ? 1 : 0) <=> (b.is_opaque? ? 1 : 0) }.uniq(&:name).sort_by(&:name)

            @objc_classes = @objc_classes.sort { |a, b| (a.is_opaque? ? 1 : 0) <=> (b.is_opaque? ? 1 : 0) }.uniq(&:name).sort_by(&:name)
            @objc_protocols = @objc_protocols.sort { |a, b| (a.is_opaque? ? 1 : 0) <=> (b.is_opaque? ? 1 : 0) }.uniq(&:name).sort_by(&:name)

            # Merge enums
            enums = @enums.map do |e|
                if e.merge_with
                    other = @enums.find { |f| e.merge_with == f.name }
                    unless other
                        raise "Cannot find other enum '#{e.merge_with}' to merge enum #{e.name} at #{Bro.location_to_s(e.location)} with"
                    end
                    other.values.push(e.values).flatten!
                    nil
                else
                    e
                end
            end
            enums = enums.find_all { |e| e }
            @enums = enums

            # Filter out functions not defined in the framework or library we're generating code for
            @functions = @functions.find_all { |f| is_included?(f) }

            # Find all functions with  inline statements create a map
            inline_statement_map = @functions.find_all { |f| f.is_inline? && f.inline_statement != nil }.map{ |f| [f.name, f.inline_statement]}.to_h

            # Filter out variadic functions
            @functions = @functions.find_all do |f|
                if f.is_variadic? || !f.parameters.empty? && f.parameters[-1].type.spelling == 'va_list'
                    definition = f.type.spelling.sub(/\(/, "#{f.name}(")
                    $stderr.puts "WARN: Ignoring 'variadic' function '#{definition}' at #{Bro.location_to_s(f.location)}"
                    false
                else
                    true
                end
            end

            # Filter out duplicate functions
            uniq_functions = @functions.uniq(&:name)
            (@functions - uniq_functions).each do |f|
                definition = f.type.spelling.sub(/\(/, "#{f.name}(")
                $stderr.puts "WARN: Ignoring duplicate function '#{definition}' at #{Bro.location_to_s(f.location)}"
            end
            @functions = uniq_functions

            # assign inline statement to uniq functions 
            @functions.find_all { |f| f.is_inline? && f.inline_statement == nil }.each{ |f| f.inline_statement = inline_statement_map[f.name]}

            # Filter out global values not defined in the framework or library we're generating code for
            @global_values = @global_values.find_all { |v| is_included?(v) }
            # Remove duplicate global values (occurs in CoreData)
            @global_values = @global_values.uniq(&:name)

            # Create global value enumerations
            @global_values.find_all(&:enum).each do |v|
                if @global_value_enums[v.enum].nil?
                    @global_value_enums[v.enum] = GlobalValueEnumeration.new self, v.enum, v
                else
                    @global_value_enums[v.enum].values.push v
                end
            end
            # Create global value dictionary wrappers
            @global_values.find_all(&:dictionary).each do |v|
                if @global_value_dictionaries[v.dictionary].nil?
                    @global_value_dictionaries[v.dictionary] = GlobalValueDictionaryWrapper.new self, v.dictionary, @global_value_enums[v.enum], v
                else
                    @global_value_dictionaries[v.dictionary].values.push v
                end
            end
            # Filter out global values that belong to an enumeration or dictionary wrapper
            @global_values = @global_values.find_all { |v| !v.enum && !v.dictionary }

            # Filter out constants not defined in the framework or library we're generating code for
            @constant_values = @constant_values.find_all { |v| is_included?(v) }
        end
    end
end

def dump_ast(cursor, indent="")
    cursor.visit_children do |cursor, _parent|
        puts "#{indent}#{cursor.kind} '#{cursor.spelling}' #{cursor.type.kind} '#{cursor.type.spelling}' #{cursor.typedef_type ? cursor.typedef_type.kind : ''}"
        dump_ast cursor, "#{indent}    "
        next :continue
    end
end

def target_file(dir, package, name)
    File.join(dir, package.gsub('.', File::SEPARATOR), "#{name}.java")
end

def load_template(dir, package, name, def_template)
    f = target_file(dir, package, name)
    FileUtils.mkdir_p(File.dirname(f))
    File.size?(f) ? IO.read(f) : def_template
end

$LICENSE_HEADER

def get_license_header()
    f = File.join(File.dirname(__FILE__), 'LICENSE.txt')

    if ($LICENSE_HEADER.nil?)
        $LICENSE_HEADER = "/*\n"
        IO.foreach(f) do |line|
            $LICENSE_HEADER += " * #{line}"
        end
        $LICENSE_HEADER += "\n */"
    end
    $LICENSE_HEADER
end

def merge_template(dir, package, name, def_template, data)
    template = load_template(dir, package, name, def_template)
    unless package.empty?
        template = template.sub(/^package .*;/, "package #{package};")
        template = template.sub(/^__LICENSE__/, get_license_header())
    end
    data.each do |key, value|
        value ||= ''
        template = template.gsub(/\/\*<#{key}>\*\/.*?\/\*<\/#{key}>\*\//m, "/*<#{key}>*/#{value}/*</#{key}>*/")
    end
    open(target_file(dir, package, name), 'wb') do |f|
        f << template
    end
end

def struct_to_java(model, data, name, struct, conf)
    data ||= {}
    inc = struct.union ? 0 : 1
    index = 0
    members = []

    # check if struct is unbounded 
    unbounded_member = nil
    unbounded_member_type = nil
    if struct.members.size > 1 && conf['skip_unbounded'] != true
        t = model.resolve_type(struct, struct.members.last.type, true, struct_member: true)
        # check if last member is candidate for unbounded struct, e.g. it either byte[], byte[0] or byte[1] (or other type than byte )
        if t.is_a?(Bro::Array) && t.dimensions.size == 1 && (t.dimensions[0] == 0 || t.dimensions[0] == 1)
            unbounded_member = struct.members.last
            unbounded_member_type = "@Array({1}) " + t.base_type.pointer.java_name
        end
    end

    struct.members.each do |e|
        mconf = conf[index] || conf[e.name] || {}
        unless mconf['exclude']
            member_name = mconf['name'] || e.name
            upcase_member_name = member_name.dup
            upcase_member_name[0] = upcase_member_name[0].capitalize

            visibility = mconf['visibility'] || 'public'
            type = mconf['type']
            if e == unbounded_member && !type
                # its last unbounded member, and its configuration is not overriden 
                # no setter is designated for it and type for it @ByVal BytePtr
                type = unbounded_member_type
                getter = 'get'

                members << "@StructMember(#{index}) #{visibility} native #{type} #{getter}#{upcase_member_name}();"
            else
                type ||= model.to_java_type(model.resolve_type(struct, e.type, true))
                getter = type == 'boolean' ? 'is' : 'get'

                members << "@StructMember(#{index}) #{visibility} native #{type} #{getter}#{upcase_member_name}();"
                # skip member setter 
                unless mconf['readonly'] == true || mconf['setter'] == false
                    members << "@StructMember(#{index}) #{visibility} native #{name} set#{upcase_member_name}(#{type} #{member_name});"
                end
            end
            members.join("\n    ")
        end
        index += inc
    end
    members = members.join("\n    ")
    data['members'] = "\n    #{members}\n    "

    unless conf['skip_def_constructor']
        constructor_params = []
        constructor_body = []
        struct.members.map do |e|
            mconf = conf[index] || conf[e.name] || {}
            next if mconf['exclude']
            next if e == unbounded_member # skip if its last member of unbounded struct 
            next if mconf['readonly'] == true || mconf['setter'] == false # skip read-only members 

            member_name = mconf['name'] || e.name
            upcase_member_name = member_name.dup
            upcase_member_name[0] = upcase_member_name[0].capitalize

            visibility = mconf['visibility'] || 'public'
            next unless visibility == 'public'
            type = mconf['type']
            type = type ? type.sub(/^(@ByVal|@Array.*)\s+/, '') : model.resolve_type(struct,e.type, true).java_name
            constructor_params.push "#{type} #{member_name}"
            constructor_body.push "this.set#{upcase_member_name}(#{member_name});"
        end.join("\n    ")
        unless constructor_params.empty?
            constructor = "public #{name}(" + constructor_params.join(', ') + ") {\n        "
            constructor += constructor_body.join("\n        ")
            constructor = "#{constructor}\n    }"
        end
        data['constructors'] = "\n    public #{name}() {}\n    #{constructor}\n    "
    end

    data['name'] = name
    data['visibility'] = conf['visibility'] || 'public'
    data['annotations'] = conf['annotations']
    if struct.packed_align != nil
        # there was a packed annotation for structure, add it to output only if was not 
        # overridden by configuration
        exiting = nil
        if data['annotations'] != nil
            data['annotations'].find { |e| e.start_with?('@Packed(') }
        end
        data['annotations'] = (data['annotations'] || []) + ["@Packed(#{struct.packed_align})"]
    end
    data['extends'] = "Struct<#{name}>"
    data['ptr'] = "public static class #{name}Ptr extends Ptr<#{name}, #{name}Ptr> {}"
    data['javadoc'] = "\n" + model.push_availability(struct).join("\n") + "\n"
    data
end

def opaque_to_java(_model, data, name, conf)
    data ||= {}
    data['name'] = name
    data['visibility'] = conf['visibility'] || 'public'
    data['extends'] = conf['extends'] || 'NativeObject'
    data['ptr'] = "public static class #{name}Ptr extends Ptr<#{name}, #{name}Ptr> {}"
    data['constructors'] = "\n    protected #{name}() {}\n    "
    data
end

def is_init?(owner, method)
    owner.is_a?(Bro::ObjCClass) && is_method_like_init?(owner, method)
end

def is_method_like_init?(owner, method)
    method.is_a?(Bro::ObjCInstanceMethod) && method.name.start_with?('init') &&
        (method.return_type.spelling == 'id' ||
         method.return_type.spelling =~ /instancetype/ ||
         method.return_type.spelling =~ /kindof\s+#{Regexp.escape(owner.name)}\s*\*/ ||
         method.return_type.spelling == "#{owner.name} *" ||
         (
            # generic
            owner.is_a?(Bro::ObjCClass) && method.return_type.spelling == "#{owner.name}" +
              "<" + owner.template_params.map{|e| e.name}.join(", ") + "> *"
         ))
end

def get_generic_type(model, owner, method, type, index, conf_type, name = nil)
    if conf_type
        conf_type =~ /<\s*([A-Z0-9])+\s+>/ ? [$1, conf_type, name, nil] : [conf_type, nil, name, nil]
    else
        if is_init?(owner, method) && index.zero?
            # init method return type should always be '@Pointer long'
            [Bro.builtins_by_name('Pointer').java_name, nil, name, nil]
        else
            resolved_type = model.resolve_type(owner, type, false, method)
            java_type = model.to_java_type(resolved_type)
            resolved_type.is_a?(Bro::ObjCId) && ["T#{index}", "T#{index} extends Object & #{java_type}", name, resolved_type] || [java_type, nil, name, resolved_type]
        end
    end
end

def property_to_java(model, owner, prop, props_conf, seen, adapter = false)
    return [] if prop.is_outdated?

    # if static -- try to get configuration for it
    conf = prop.is_static? ? model.get_conf_for_key("+" + prop.name, props_conf) : nil
    # sanity check for regexp, as + can get into name, just for compatibility mode
    conf = nil if conf && ((!conf['getter'].nil? && conf['getter'].start_with?('+')) || (!conf['setter'].nil? && conf['setter'].start_with?('+')) || (!conf['name'].nil? && conf['name'].start_with?('+')))
    # if not found try to look for regular one (comp mode)
    conf ||= model.get_conf_for_key(prop.name, props_conf) || {}

    if !conf['exclude']
        name = conf['name'] || prop.name

        return [] if adapter && conf['skip_adapter']

        type = get_generic_type(model, owner, prop, prop.type, 0, conf['type'])
        omit_prefix = conf['omit_prefix'] || false

        getter = ''
        getter = if !conf['getter'].nil?
                     conf['getter']
                 else
                     model.getter_for_name(name, type[0], omit_prefix)
                 end
        setter = ''
        setter = if !conf['setter'].nil?
                     conf['setter']
                 else
                     model.setter_for_name(name, omit_prefix)
                 end
        visibility = conf['visibility'] ||
                     owner.is_a?(Bro::ObjCClass) && 'public' ||
                     owner.is_a?(Bro::ObjCCategory) && 'public' ||
                     adapter && 'public' ||
                     owner.is_a?(Bro::ObjCProtocol) && model.get_protocol_conf(owner.name)['class'] && 'public' ||
                     ''
        native = owner.is_a?(Bro::ObjCProtocol) && !model.get_protocol_conf(owner.name)['class'] ? '' : (adapter ? '' : 'native')
        static = owner.is_a?(Bro::ObjCCategory) || prop.is_static? ? 'static' : ''
        generics_s = [type].map { |e| e[1] }.find_all { |e| e }.join(', ')
        generics_s = !generics_s.empty? ? "<#{generics_s}>" : ''
        param_types = []
        if owner.is_a?(Bro::ObjCCategory)
            cconf = model.get_category_conf(owner.owner.nil? ? owner.name : owner.owner)
            thiz_type = conf['owner_type'] || cconf && cconf['owner_type'] || owner.owner || owner.name
            param_types.unshift([thiz_type, nil, 'thiz'])
        end
        parameters_s = param_types.map { |p| "#{p[0]} #{p[2]}" }.join(', ')
        body = ';'
        if adapter
            t = type[0].split(' ')
            default_value = conf['default'] || model.default_value_for_type(t.last)
            body = " { return #{default_value}; }"
        end

        marshaler = conf['marshaler'] ? "@org.robovm.rt.bro.annotation.Marshaler(#{conf['marshaler']}.class)" : ''

        annotations = conf['annotations'] && !conf['annotations'].empty? ? conf['annotations'].uniq.join(' ') : nil

        lines = []
        seen_prefix = !static.empty? ? '+' : '-'
        unless seen["#{seen_prefix}#{prop.getter_name}"]
            model.push_availability(prop, lines)
            lines << annotations.to_s if annotations

            lines << if adapter
                         "@NotImplemented(\"#{prop.getter_name}\")"
                     else
                         "@Property(selector = \"#{prop.getter_name}\")"
                     end
            lines << "#{[visibility, static, native, marshaler, generics_s, type[0], getter].find_all { |e| !e.empty? }.join(' ')}(#{parameters_s})#{body}"
            seen["#{seen_prefix}#{prop.getter_name}"] = true
        end

        if !prop.is_readonly? && !conf['readonly'] && !seen["#{seen_prefix}#{prop.setter_name}"]
            param_types.push([type[0], nil, 'v'])
            parameters_s = param_types.map { |p| "#{p[0]} #{p[2]}" }.join(', ')
            model.push_availability(prop, lines)
            lines << annotations.to_s if annotations
            if adapter
                lines << "@NotImplemented(\"#{prop.setter_name}\")"
                body = ' {}'
            elsif (prop.attrs['assign'] || prop.attrs['weak'] || conf['strong']) && !conf['weak']
                # assign is used on some properties of primitives, structs and enums which isn't needed
                if type[0] =~ /^@(ByVal|MachineSized|Pointer)/ || type[0] =~ /\b(boolean|byte|short|char|int|long|float|double)$/ || type[3] && type[3].is_a?(Bro::Enum)
                    lines << "@Property(selector = \"#{prop.setter_name}\")"
                else
                    lines << "@Property(selector = \"#{prop.setter_name}\", strongRef = true)"
                end
            else
                lines << "@Property(selector = \"#{prop.setter_name}\")"
            end
            marshaler = marshaler + ' ' if marshaler != ''

            lines << "#{[visibility, static, native, generics_s, 'void', setter].find_all { |e| !e.empty? }.join(' ')}(#{marshaler}#{parameters_s})#{body}"
            seen["#{seen_prefix}#{prop.setter_name}"] = true
        end
        lines
    else
        []
    end
end


# configuration for method is passed explicitly as parameter now and has to be resolved externally
# this is done to allow method configuration to be inherited from parent classes
def method_to_java(model, owner_name, owner, method_owner, method, conf, seen, adapter = false, prot_as_class = false,
                   inherited_initializers = false)
    return [[], []] if method.is_outdated? || method.is_a?(Bro::ObjCClassMethod) && owner.is_a?(Bro::ObjCProtocol)

    return [[], []] if owner.is_a?(Bro::ObjCProtocol) && is_method_like_init?(owner, method)

    full_name = (method.is_a?(Bro::ObjCClassMethod) ? '+' : '-') + method.name

    return [[], []] if full_name == '-init' # ignore designated initializers

    return [[], []] if adapter && conf['skip_adapter']

    return [[], []] if method.is_a?(Bro::ObjCClassMethod) && method.is_class_property?

    if seen[full_name] || conf['exclude']
        [[], []]
    elsif method.is_variadic? || !method.parameters.empty? && method.parameters[-1].type.spelling == 'va_list'
        param_types = method.parameters.map { |e| e.type.spelling }
        param_types.push('...') if method.is_variadic?
        $stderr.puts "WARN: Ignoring variadic method '#{owner.name}.#{method.name}(#{param_types.join(', ')})' at #{Bro.location_to_s(method.location)}"
        [[], []]
    elsif !conf['exclude']
        # is used to produce hints for faster yaml file construction
        suggestion_data = nil
        # dkimitsa: if not specified in config(get here as nil) -- consider as false
        prot_as_class = false if prot_as_class == nil
        ret_type = get_generic_type(model, owner, method, method.return_type, 0, conf['return_type'])
        params_conf = conf['parameters'] || {}
        param_types = method.parameters.each_with_object([]) do |p, l|
            index = l.size + 1
            pconf = params_conf[p.name] || params_conf[l.size] || {}
            pmarshaler = pconf['marshaler'] ? "@org.robovm.rt.bro.annotation.Marshaler(#{pconf['marshaler']}.class) " : ''
            l.push(get_generic_type(model, owner, method, p.type, index, pconf['type'], pconf['name'] || p.name).push(pmarshaler))
            l
        end
        name = conf['name']
        unless name
            if method.name.end_with?(':') && method.name.count(':') == 1
                # dont attach $ char to one parameter method, just remove it
                name = method.name[0..-2]
                suggestion_data = [full_name, name] if name.include?("With")
            else
                name = method.name.tr(':', '$')
                # report this case in suggestion_data to point dev that this method
                # will receive $$ in the name
                suggestion_data = [full_name, name] if !conf['trim_after_first_colon'] && (name.count('$') > 0)
            end
            if method.parameters.empty? && method.return_type.kind != :type_void && conf['property']
                base = name[0, 1].upcase + name[1..-1]
                name = ret_type[0] == 'boolean' ? "is#{base}" : "get#{base}"
            elsif method.name.start_with?('set') && method.name.size > 3 && method.parameters.size == 1 && method.return_type.kind == :type_void # && conf['property']
                name = name.sub(/\$$/, '')
            elsif conf['trim_after_first_colon']
                name = name.sub(/\$.*/, '')
            end
        end
        # Default visibility is protected for init methods, public for other methods in classes and empty (public) for interface methods.
        visibility = conf['visibility'] ||
                     owner.is_a?(Bro::ObjCClass) && (is_init?(owner, method) ? 'protected' : 'public') ||
                     owner.is_a?(Bro::ObjCCategory) && 'public' ||
                     adapter && 'public' ||
                     owner.is_a?(Bro::ObjCProtocol) && model.get_protocol_conf(owner.name)['class'] && 'public' ||
                     ''
        native = owner.is_a?(Bro::ObjCProtocol) && !model.get_protocol_conf(owner.name)['class'] ||
            (owner.is_a?(Bro::ObjCCategory) && method.is_a?(Bro::ObjCClassMethod)) ? '' : (adapter ? '' : 'native')
        is_static = method.is_a?(Bro::ObjCClassMethod) || owner.is_a?(Bro::ObjCCategory)
        static = is_static ? 'static' : ''

        generics_s = ([ret_type] + param_types).map { |e| e[1] }.find_all { |e| e }.join(', ')
        generics_s = !generics_s.empty? ? "<#{generics_s}>" : ''

        if owner.is_a?(Bro::ObjCCategory)
            if method.is_a?(Bro::ObjCInstanceMethod)
                cconf = model.get_category_conf(owner.owner)
                thiz_type = conf['owner_type'] || cconf && cconf['owner_type'] || owner.owner
                param_types.unshift([thiz_type, nil, 'thiz'])
            end
        end
        parameters_s = param_types.map { |p| "#{p[4]}#{p[0]} #{p[2]}" }.join(', ')

        ret_marshaler = conf['return_marshaler'] ? "@org.robovm.rt.bro.annotation.Marshaler(#{conf['return_marshaler']}.class)" : ''

        ret_anno = ''
        if !generics_s.empty? && ret_type[0] =~ /^(@Pointer|@ByVal|@MachineSizedFloat|@MachineSizedSInt|@MachineSizedUInt)/
            # Generic types and an annotated return type. Move the annotation before the generic type info
            ret_anno = $1
            ret_type[0] = ret_type[0].sub(/^@.*\s+(.*)$/, '\1')
        end
        body = ';'
        if adapter
            t = ret_type[0].split(' ')
            if t.last == 'void'
                body = ' {}'
            else
                default_value = conf['default'] || model.default_value_for_type(t.last)
                body = " { return #{default_value}; }"
            end
        end
        method_lines = []
        constructor_lines = []

        annotations = conf['annotations'] && !conf['annotations'].empty? ? conf['annotations'].uniq.join(' ') : nil
        static_constructor = !conf['constructor'].nil? && conf['constructor'] == true && is_static
        # introduced constructor wrapper to be able solve cases when there are two init* methods with same arguments
        # which makes impossible to create two constructors in java
        static_constructor_name = is_static ? nil : conf['static_constructor_name']
        suggestion_data = nil if static_constructor_name # reset any name suggestions as static_constructor_name will provide the name

        if conf['throws']
            error_type = 'NSError'
            case conf['throws']
            when 'CFStreamErrorException'
                error_type = 'CFStreamError'
            end

            throw_parameters_s = param_types.map { |p| "#{p[0]} #{p[2]}" }[0..-2].join(', ')
            throw_params = param_types[0..-2].map {|e| e[2].to_s }
            throw_args_s = throw_params.length.zero? ? 'ptr' : "#{throw_params.join(', ')}, ptr"

            unless owner.is_a?(Bro::ObjCProtocol) && prot_as_class == false || owner.is_a?(Bro::ObjCClass) && is_init?(owner, method) || static_constructor
                model.push_availability(method, method_lines)

                method_lines << annotations.to_s if annotations
                method_lines << "#{[visibility, static, generics_s, ret_type[0], name].find_all { |e| !e.empty? }.join(' ')}(#{throw_parameters_s}) throws #{conf['throws']} {"
                method_lines << "   #{error_type}.#{error_type}Ptr ptr = new #{error_type}.#{error_type}Ptr();"
                ret = ret_type[0].gsub(/@[a-zA-Z0-9_().]+ /, '').gsub(/\<.*\> /, '') # Trim annotations
                ret = ret == 'void' ? '' : "#{ret} result = "
                method_lines << "   #{ret}#{name}(#{throw_args_s});"
                method_lines << "   if (ptr.get() != null) { throw new #{conf['throws']}(ptr.get()); }"
                method_lines << '   return result;' unless ret == ''
                method_lines << '}'
            end

            visibility = 'private' unless !is_static && method_owner.is_a?(Bro::ObjCProtocol) ||
                                          owner.is_a?(Bro::ObjCProtocol) && prot_as_class == false
        end

        if ((is_static && static_constructor) || (is_init?(owner, method) && !static_constructor_name.nil?))
            # do not override ret_type if it was customized through config
            ret_type[0] = "@Pointer long" unless conf['return_type']
            visibility = 'protected'
        end

        unless inherited_initializers
            # do not add native method declaration if it is inherited initializer.
            # constructor will call super
            model.push_availability(method, method_lines)
            method_lines << annotations.to_s if annotations
            method_lines << if adapter
                                "@NotImplemented(\"#{method.name}\")"
                            else
                                "@Method(selector = \"#{method.name}\")"
                            end

            if owner.is_a?(Bro::ObjCCategory) && method.is_a?(Bro::ObjCClassMethod)
                cat_parameters_s = (['ObjCClass clazz'] + (param_types.map { |p| "#{p[0]} #{p[2]}" })).join(', ')
                method_lines << "protected static native #{[ret_marshaler, ret_anno, generics_s, ret_type[0], name].find_all { |e| !e.empty? }.join(' ')}(#{cat_parameters_s});"
                args_s = (["ObjCClass.getByType(#{owner.owner}.class)"] + (param_types.map { |p| p[2] })).join(', ')
                body = " { #{ret_type[0] != 'void' ? 'return ' : ''}#{name}(#{args_s}); }"
            end
            method_lines.push("#{[visibility, static, native, ret_marshaler, ret_anno, generics_s, ret_type[0], name].find_all { |e| !e.empty? }.join(' ')}(#{parameters_s})#{body}")
        end
        if owner.is_a?(Bro::ObjCClass) && conf['constructor'] != false && (is_init?(owner, method) || static_constructor)
            constructor_visibility = conf['constructor_visibility'] || 'public'

            # parameters might be requested to be packed in tuple 
            if conf['arguments_tuple'] != nil        
                tuple_name = conf['arguments_tuple']
                # replace parameters with tuple 
                if conf['throws']
                    tuple_member_types = param_types[0..-2]
                    tuple_constructor_params = throw_parameters_s
                    throw_parameters_s = tuple_name + " tuple"
                    throw_args_s = inherited_initializers ? "tuple" : param_types[0..-2].map { |p| "tuple." + p[2] }.push('ptr').join(', ')
                else
                    tuple_member_types = param_types
                    tuple_constructor_params = parameters_s
                    parameters_s = tuple_name + " tuple"
                    args_s = inherited_initializers ? "tuple" : param_types.map { |p| "tuple." + p[2] }.join(', ')
                end
                
                # add tuple class definition
                unless inherited_initializers
                    constructor_lines << ""
                    constructor_lines << "/** argument tuple for constructor bellow */"
                    constructor_lines << "public static class #{tuple_name} {"
                    tuple_member_types.map { |p| "   public final #{p[0]} #{p[2]};" }.each { |line| constructor_lines << line }
                    constructor_lines << "   public #{tuple_name}(#{tuple_constructor_params}) {"
                    tuple_member_types.map { |p| "      this.#{p[2]} = #{p[2]};"}.each { |line| constructor_lines << line }
                    constructor_lines << "   }"
                    constructor_lines << "}"
                end
            else 
                args_s = param_types.map { |p| p[2] }.join(', ')
            end

            model.push_availability(method, constructor_lines)
            constructor_lines << annotations.to_s if annotations

            if is_init?(owner, method) && !static_constructor_name.nil?
                # creating static wrapper to call corresponding init
                constructor_lines << "@Method(selector = \"#{method.name}\")"
                if conf['throws']
                    constructor_lines << "#{constructor_visibility} static #{generics_s.size>0 ? ' ' + generics_s : ''} #{owner_name} #{static_constructor_name}(#{throw_parameters_s}) throws #{conf['throws']}  {"
                    constructor_lines << "   #{owner_name} res = new #{owner_name}((SkipInit) null);"
                    constructor_lines << "   #{error_type}.#{error_type}Ptr ptr = new #{error_type}.#{error_type}Ptr();"
                    constructor_lines << "   res.initObject(res.#{name}(#{throw_args_s}));"
                    constructor_lines << "   if (ptr.get() != null) { throw new #{conf['throws']}(ptr.get()); }"
                    constructor_lines << "   return res;"
                    constructor_lines << "}"
                else
                    constructor_lines << "#{constructor_visibility} static #{generics_s.size>0 ? ' ' + generics_s : ''} #{owner_name} #{static_constructor_name}(#{parameters_s}) {"
                    constructor_lines << "   #{owner_name} res = new #{owner_name}((SkipInit) null);"
                    constructor_lines << "   res.initObject(res.#{name}(#{args_s}));"
                    constructor_lines << "   return res;"
                    constructor_lines << "}"
                end
            elsif is_init?(owner, method) && inherited_initializers
				# init method added from super class as inherited initializer
				# in this case native method is not generated and constructor
				# is implemented with only super call to presave java way of initialization
				# however it is possible to declare native method and just call it
				# but it block any possible initialization in super java part
				constructor_lines << "@Method(selector = \"#{method.name}\")"
				if conf['throws']
				    constructor_lines << "#{constructor_visibility}#{!generics_s.empty? ? ' ' + generics_s : ''} #{owner_name}(#{throw_parameters_s}) throws #{conf['throws']} { super(#{throw_params.join(', ')}); }"
				else
				    constructor_lines << "#{constructor_visibility}#{!generics_s.empty? ? ' ' + generics_s : ''} #{owner_name}(#{parameters_s}) { super(#{args_s}); }"
				end
            elsif is_init?(owner, method)
                constructor_lines << "@Method(selector = \"#{method.name}\")"
                if conf['throws']
                    constructor_lines << "#{constructor_visibility}#{!generics_s.empty? ? ' ' + generics_s : ''} #{owner_name}(#{throw_parameters_s}) throws #{conf['throws']} {"
                    constructor_lines << "   super((SkipInit) null);"
                    constructor_lines << "   #{error_type}.#{error_type}Ptr ptr = new #{error_type}.#{error_type}Ptr();"
                    constructor_lines << "   long handle = #{name}(#{throw_args_s});"
                    constructor_lines << "   if (ptr.get() != null) { throw new #{conf['throws']}(ptr.get()); }"
                    constructor_lines << "   initObject(handle);"
                    constructor_lines << "}"
                else
                    constructor_lines << "#{constructor_visibility}#{!generics_s.empty? ? ' ' + generics_s : ''} #{owner_name}(#{parameters_s}) { super((SkipInit) null); initObject(#{name}(#{args_s})); }"
                end
            elsif (static_constructor)
                # skip retain if ownership is not required as per apple doc
                skip_retain = name.start_with?('new') || name.start_with?('alloc') || name.start_with?('copy') || name.start_with?('mutableCopy')
                if conf['throws']
                    args_s2 = param_types[0..-2].map { |p| p[2] }.join(', ')

                    constructor_lines << "#{constructor_visibility}#{!generics_s.empty? ? ' ' + generics_s : ''} #{owner_name}(#{throw_parameters_s}) throws #{conf['throws']} {"
                    constructor_lines << "   this(#{args_s2}, new #{error_type}.#{error_type}Ptr());"
                    constructor_lines << "}"
                    constructor_lines << "private#{!generics_s.empty? ? ' ' + generics_s : ''} #{owner_name}(#{throw_parameters_s}, #{error_type}.#{error_type}Ptr ptr) throws #{conf['throws']} {"
                    constructor_lines << "   super((Handle) null, #{name}(#{args_s2}, ptr));"
                    constructor_lines << "   retain(getHandle());" unless skip_retain
                    constructor_lines << "   if (ptr.get() != null) { throw new #{conf['throws']}(ptr.get()); }"
                    constructor_lines << "}"
                else
                    constructor_lines << "#{constructor_visibility}#{generics_s.size>0 ? ' ' + generics_s : ''} #{owner_name}(#{parameters_s}) { super((Handle) null, #{name}(#{args_s})); #{skip_retain ? '' : "retain(getHandle());"} }"
                end
            end
        end
        seen[full_name] = true
        [method_lines, constructor_lines, suggestion_data]
    else
        [[], []]
    end
end

class ClangPreprocessorInclude
    attr_accessor :name, :file
    def initialize(name, write_name, parent = nil)
        @name = name
        @parent = parent
        dirname = File.dirname(write_name)
        FileUtils.mkdir_p(dirname) unless File.directory?(dirname)
        @file = File.open(write_name, "w")
    end

    def write_string(s)
        file.puts s
    end

    def close
        return unless file
        file.close
        file = nil
    end
end


def clang_preprocess(headers, args)
    file_idx = 1
    include_stack = []
    tmp_dir = Dir.mktmpdir()
    at_exit { FileUtils.remove_entry(tmp_dir)}
    main_file = nil

    # prepare MACRO overrides to save NS_OPTIONS macro as it is usefull for
    # generating BIT enums
    overrides_h = File.join(tmp_dir, '__overrides.h')
    File.open(overrides_h, 'w') do |f|
        f.puts "#import <Foundation/NSObjCRuntime.h>"
        f.puts "#undef NS_OPTIONS"
        f.puts "#undef CF_OPTIONS"
    end

    headers_h = File.join(tmp_dir, '__headers.h')
    File.open(headers_h, 'w') do |f|
        headers.each do |header|
            if (header.start_with?("#") || header.start_with?("@"))
                f.puts header
            else
                f.puts "#include \"#{header}\""
            end
        end
    end

    lines = IO.popen(['clang'] + args + [headers_h, '-include', overrides_h]).readlines
    lines.each do |line|
        if !line.start_with?('# ')
            # data line
            raise "Unexpected data line while includes are empty #{line}" unless include_stack.length
            # skip overrides data
            next if include_stack.last.name == overrides_h
            # copy data
            include_stack.last.write_string line
            next
        end

        line.strip
        if !(line =~ /^# (?:\d+) \"(.*)\"\ ?([\d\ ]+)?$/)
            raise "Unable to parse preprocessor line marker: #{line}"
        end

        file_name = $1
        args = $2 ? $2.split(' ') : []


        file_name = File.expand_path(file_name)
        if args.length == 0
            next unless include_stack.empty?

            main_file = File.join(tmp_dir, file_name)
            include_stack.push ClangPreprocessorInclude.new(file_name, main_file)
        elsif args.include?('1')
            raise "there is no main file while including header" if include_stack.empty?

            # entering into file
            write_file_name = File.join(tmp_dir, file_name + ".#{file_idx}.h")
            file_idx += 1
            include_stack.last.write_string "\#include \"#{write_file_name}\""
            include_stack.push ClangPreprocessorInclude.new(file_name, write_file_name)
        elsif args.include?('2')
            # exiting from file
            while include_stack.last.name != file_name
                include_stack.last.close
                include_stack.pop
            end
        end
    end

    while !include_stack.empty?
        include_stack.last.close
        include_stack.pop
    end

    main_file = File.expand_path(main_file)

    #now restore macro just to have them there
    restores_main_h = File.join(tmp_dir, '__restores.h')
    File.open(restores_main_h, 'w') do |f|
        f.puts "#define NS_OPTIONS(_type, _name) enum _name : _type _name; enum _name : _type"
        f.puts "#define CF_OPTIONS(_type, _name) enum _name : _type _name; enum _name : _type"
        f.puts "#import \"#{main_file}\""
    end
    return restores_main_h
end


# limits
UCHAR_MAX = 255
CHAR_MAX = 127
CHAR_MIN = (-128)
USHRT_MAX = 65535
SHRT_MAX = 32767
SHRT_MIN = (-32768)
UINT_MAX = 0xffff_ffff
INT_MAX = 2147483647
INT_MIN = (-2147483647-1)
ULONG_MAX = 0xffff_ffff_ffff_ffff
LONG_MAX = 0x7fff_ffff_ffff_ffff
LONG_MIN = (-0x7fff_ffff_ffff_ffff-1)

$mac_version = nil
$ios_version = '17'
$ios_version_min_usable = '8.0' # minimal version robovm to be used on, all since notification will be suppressed if ver <= 8.0
$target_platform = 'ios'
xcode_dir = `xcode-select -p`.chomp
sysroot = "#{xcode_dir}/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk"

# environment variables that enables debug/tools modules 
$dbg_dump_inline_fn = ENV.has_key?('BRO_DUMP_INLINE')  # generates inline functions with their original code in comments 

script_dir = File.expand_path(File.dirname(__FILE__))
target_dir = ARGV[0]
templates_dir = script_dir + '/templates'
def_class_template = IO.read("#{templates_dir}/class_template.java")
def_enum_template = IO.read("#{templates_dir}/enum_template.java")
def_bits_template = IO.read("#{templates_dir}/bits_template.java")
def_protocol_template = IO.read("#{templates_dir}/protocol_template.java")
def_value_enum_template = IO.read("#{templates_dir}/value_enum_template.java")
def_value_dictionary_template = IO.read("#{templates_dir}/value_dictionary_template.java")
def_nserror_enum_template = IO.read("#{templates_dir}/nserror_enum_template.java")
global = YAML.load_file("#{script_dir}/global.yaml")

ARGV[1..-1].each do |yaml_file|
    puts "Processing #{yaml_file}..."
    conf = YAML.load_file(yaml_file)

    framework = conf['framework']

    headers = []
    headers.push(conf['header']) if conf['header']
    headers.concat(conf['headers']) if conf['headers']
    abort("Required 'header' or 'headers' value missing in #{yaml_file}") if headers.empty?

    conf = global.merge conf
    conf['typedefs'] = (global['typedefs'] || {}).merge(conf['typedefs'] || {}).merge(conf['private_typedefs'] || {})
    conf['structdefs'] = (global['structdefs'] || {}).merge(conf['structdefs'] || {}).merge(conf['private_structdefs'] || {})
    conf['generic_typedefs'] = (global['generic_typedefs'] || {}).merge(conf['generic_typedefs'] || {}).merge(conf['generic_typedefs'] || {})

    framework_roots = []

    if conf['header_root']
        framework_roots[0] = File.expand_path(File.dirname(yaml_file)) + "/" + conf['header_root']
        header_root = framework_roots[0]
    elsif File.exist?(File.expand_path(File.dirname(yaml_file)) + "/#{framework}.lib/Headers") # RoboPods Library
        framework_roots[0] = File.expand_path(File.dirname(yaml_file))
        header_root = framework_roots[0] + "/#{framework}.lib/Headers"
    elsif File.exist?(File.expand_path(File.dirname(yaml_file)) + "/#{framework}.framework/Headers") # RoboPods Framework
        framework_roots[0] = File.expand_path(File.dirname(yaml_file))
        header_root = framework_roots[0] + "/#{framework}.framework/Headers"
    elsif File.exist?(File.expand_path(File.dirname(yaml_file)) + "/../robopods/META-INF/robovm/ios/libs/#{framework}.framework/Headers") # RoboPods Framework
        framework_roots[0] = File.expand_path(File.dirname(yaml_file)) + "/../robopods/META-INF/robovm/ios/libs"
        header_root = framework_roots[0] + "/#{framework}.framework/Headers"
    else
        framework_roots[0] = sysroot
        header_root = framework_roots[0]
    end

    imports = []
    imports << 'java.io.*'
    imports << 'java.nio.*'
    imports << 'java.util.*'
    imports << 'org.robovm.objc.*'
    imports << 'org.robovm.objc.annotation.*'
    imports << 'org.robovm.objc.block.*'
    imports << 'org.robovm.rt.*'
    imports << 'org.robovm.rt.annotation.*'
    imports << 'org.robovm.rt.bro.*'
    imports << 'org.robovm.rt.bro.annotation.*'
    imports << 'org.robovm.rt.bro.ptr.*'
    imports += (conf['imports'] || [])

    (conf['include'] || []).each do |f|
        custom_framework = f.include?('.yaml')

        if (!f.include?('.'))
            ['robovm', 'mobi-robovm', 'mobirobovm'].each do |robovm_folder|
                file_name = "#{script_dir}/../#{robovm_folder}/compiler/cocoatouch/src/main/bro-gen/#{f}.yaml"
                if (File.exist?(file_name))
                    f = file_name
                    break
                end
            end
        else
            f = Pathname.new(yaml_file).parent + f
        end

        c = YAML.load_file(f)
        # Excluded all classes in included config
        c_classes = (c['classes'] || {}).each_with_object({}) { |(k, v), h| v ||= {}; v['transitive'] = true; h[k] = v; h }
        conf['classes'] = c_classes.merge(conf['classes'] || {})
        c_protocols = (c['protocols'] || {}).each_with_object({}) { |(k, v), h| v ||= {}; v['transitive'] = true; h[k] = v; h }
        conf['protocols'] = c_protocols.merge(conf['protocols'] || {})
        c_enums = (c['enums'] || {}).each_with_object({}) { |(k, v), h| v ||= {}; v['transitive'] = true; h[k] = v; h }
        conf['enums'] = c_enums.merge(conf['enums'] || {})
        c_typed_enums = (c['typed_enums'] || {}).each_with_object({}) { |(k, v), h| v ||= {}; v['transitive'] = true; h[k] = v; h }
        conf['typed_enums'] = c_typed_enums.merge(conf['typed_enums'] || {})
        conf['typedefs'] = (c['typedefs'] || {}).merge(conf['typedefs'] || {})
        conf['structdefs'] = (c['structdefs'] || {}).merge(conf['structdefs'] || {})
        conf['generic_typedefs'] = (c['generic_typedefs'] || {}).merge(conf['generic_typedefs'] || {})
        conf['annotations'] = (c['annotations'] || []).concat(conf['annotations'] || [])
        if conf['merge_vals_consts_functs']
            # TODO: this is experimental and required for AudioUnit only for now
            # copy and exclude also functions/values/consts other than trap
            # it is required for AudioToolBox module as it includes AudioUnit entities
            # which causes baunch of duplicates to appear in ToolBox from AudioUnit
            c_functions = (c['functions'] || {}).find_all{|k, v| v['name'] != 'Function__#{g[0]}'}.each_with_object({}) { |(k, v), h| v ||= {}; v['transitive'] = true; h[k] = v; h }
            conf['functions'] = c_functions.merge(conf['functions'] || {})
            c_values = (c['values'] || {}).find_all{|k, v| v['name'] != 'Value__#{g[0]}'}.each_with_object({}) { |(k, v), h| v ||= {}; v['transitive'] = true; h[k] = v; h }
            conf['values'] = c_values.merge(conf['values'] || {})
            c_constants = (c['constants'] || {}).find_all{|k, v| v['name'] != 'Constant__#{g[0]}'}.each_with_object({}) { |(k, v), h| v ||= {}; v['transitive'] = true; h[k] = v; h }
            conf['constants'] = c_constants.merge(conf['constants'] || {})
        end

        imports.push("#{c['package']}.*") if c['package']

        if custom_framework
            framework_roots << File.dirname(f)
        end
    end

    $library = if conf['library'] && conf['library'] != 'Library.INTERNAL'
                   "\"#{conf['library']}\""
               else
                   'Library.INTERNAL'
               end

    imports.uniq!

    index = FFI::Clang::Index.new
    clang_preprocess_args = ['-E', '-dD', '-target', "arm64-apple-ios#{$ios_version}", '-fblocks', '-isysroot', sysroot]
    clang_args = ['-target', "arm64-apple-ios#{$ios_version}", '-fblocks']

    clang_headers = []
    headers.each do |e|
        if (e.start_with?("#") || e.start_with?("@"))
            # push as it is without extending the path
            clang_headers.push(e)
        else
            clang_headers.push(File.join(header_root, e))
        end
    end

    framework_roots.each do |e|
        clang_preprocess_args << "-F#{e}" if e != sysroot
    end

    clang_preprocess_args += conf['clang_args'] if conf['clang_args']
    clang_args += conf['clang_args'] if conf['clang_args']

    # preprocess files using clang to expand all macro to be able better understand
    # attributes and enum/types definitions
    main_file = clang_preprocess(clang_headers, clang_preprocess_args)

    # START of potential support code block
    # this map will contain all potential entries that are missing (such as class is not covered in yaml)
    # or has be updated (such as method name generated with $$$)
    $potential_new_entries = {}
    def add_potential_new_entry(entry, data)
        exists = $potential_new_entries.key?(entry)
        bundle = exists ? $potential_new_entries[entry] : nil
        if data
            bundle ||= []
            bundle.push(data)
        end
        $potential_new_entries[entry] = bundle if !exists
    end
    # END of potential support code block

    # now translate pre-processed
    translation_unit = index.parse_translation_unit(main_file, clang_args, [], detailed_preprocessing_record: true)
    translation_unit.diagnostics.each do |e|
         if (e.severity == :error)
            $stderr.puts "Err: #{e.category} #{e.spelling} @ #{e.location.file} #{e.location.line}:#{e.location.column}"
            e.children.each do |c|
                $stderr.puts "    #{c.spelling}"
            end
         end
    end

    model = Bro::Model.new conf
    model.process(translation_unit.cursor)

    package = conf['package'] || ''
    default_class = conf['default_class'] || conf['framework'] || 'Functions'

    template_datas = {}

    # enum helpers

    # returns storage type from marshaller
    def enum_storage_type_from_marshaler(marshaller)
        return case marshaller
            when 'ValuedEnum.AsSignedByteMarshaler'       then 'signed char'
            when 'ValuedEnum.AsUnsignedByteMarshaler'     then 'unsigned char'
            when 'ValuedEnum.AsSignedShortMarshaler'      then 'signed short'
            when 'ValuedEnum.AsUnsignedShortMarshaler'    then 'unsigned short'
            when 'ValuedEnum.AsSignedIntMarshaler'        then 'signed int'
            when 'ValuedEnum.AsUnsignedIntMarshaler'      then 'unsigned int'
            when 'ValuedEnum.AsLongMarshaler'             then 'signed long'
            when 'ValuedEnum.AsMachineSizedSIntMarshaler' then 'MachineSInt'
            when 'ValuedEnum.AsMachineSizedUIntMarshaler' then 'MachineUInt'

            when 'Bits.AsByteMarshaler'                   then 'unsigned char'
            when 'Bits.AsShortMarshaler'                  then 'unsigned short'
            when 'Bits.AsIntMarshaler'                    then 'unsigned int'
            when 'Bits.AsLongMarshaler'                   then 'unsigned long'
            when 'Bits.AsMachineSizedIntMarshaler'        then 'MachineUInt'
            else nil
        end
    end

    # finds required marshaler for given storrage type
    def enum_marshaler_from_storrage_type(storage_type, is_bits)
        if is_bits == nil || is_bits == false
            return case storage_type
                when 'MachineSInt'    then 'ValuedEnum.AsMachineSizedSIntMarshaler'
                when 'MachineUInt'    then 'ValuedEnum.AsMachineSizedUIntMarshaler'
                when 'signed char'    then 'ValuedEnum.AsSignedByteMarshaler'
                when 'unsigned char'  then 'ValuedEnum.AsUnsignedByteMarshaler'
                when 'signed short'   then 'ValuedEnum.AsSignedShortMarshaler'
                when 'unsigned short' then 'ValuedEnum.AsUnsignedShortMarshaler'
                when 'unsigned int'   then 'ValuedEnum.AsUnsignedIntMarshaler'
                when 'signed long'    then 'ValuedEnum.AsLongMarshaler'
                when 'unsigned long'  then 'ValuedEnum.AsLongMarshaler'
                else nil
            end
        else
            return case storage_type
                when 'MachineSInt', 'MachineUInt'     then 'Bits.AsMachineSizedIntMarshaler'
                when 'signed char', 'unsigned char'   then 'Bits.AsByteMarshaler'
                when 'signed short', 'unsigned short' then 'Bits.AsShortMarshaler'
                when 'signed int', 'unsigned int'     then 'Bits.AsIntMarshaler'
                when 'signed long', 'unsigned long'   then 'Bits.AsLongMarshaler'
                else nil
            end
        end
    end

    # returns enum storage type limits
    def enum_storage_type_limits(enum, storage_type)
        # find outs ranges depending on storage type
        # min, max -- natural limits of storage type
        v_min, v_max = case storage_type
            #                           min       max
            when 'MachineSInt'    then [INT_MIN,  INT_MAX]
            when 'MachineUInt'    then [0,        UINT_MAX]
            when 'signed char'    then [CHAR_MIN, CHAR_MAX]
            when 'unsigned char'  then [0,        UCHAR_MAX]
            when 'signed short'   then [SHRT_MIN, SHRT_MAX]
            when 'unsigned short' then [0,        USHRT_MAX]
            when 'signed int'     then [INT_MIN,  INT_MAX]
            when 'unsigned int'   then [0,        UINT_MAX]
            when 'signed long'    then [LONG_MIN, LONG_MAX]
            when 'unsigned long'  then [0,        ULONG_MAX]
            else raise "Unexpected storage type #{storage_type} for enum #{enum.name}"
        end

        return [v_min, v_max]
    end

    # returns true if value fits enum limits
    def enum_entry_fits_limits(value, storage_type, storage_limits)
        # handle special corner cases of platform dependant integers
        if storage_type == 'MachineUInt' && value == ULONG_MAX
            # We assume NSUIntegerMax
            return true
        elsif @type.spelling == 'MachineSInt' && value == LONG_MAX
            # We assume NSIntegerMax
            return true
        elsif @type.spelling == 'MachineSInt' && value == LONG_MIN
            # We assume NSIntegerMin
            return true
        end

        v_min, v_max = storage_type_limits
        return value >= v_min && value <= v_max
    end

    # converts negative signed in to unsigned values
    # as long unsigned are retuned as negative values
    def enum_normalize_unsigned(value, storage_type)
        if storage_type == 'MachineUInt' || storage_type == 'unsigned long'
            value = [value].pack("q").unpack('Q').first
        elsif storage_type == 'unsigned int'
            value = [value].pack("l").unpack('L').first
        elsif storage_type == 'unsigned short'
            value = [value].pack("s").unpack('S').first
        elsif storage_type == 'unsigned char'
            value = [value].pack("c").unpack('C').first
        end
        return value
    end

    # returns sting presentation of entry to be used as java source code
    def enum_entry_java_value(value, storage_type)
        # handle special corner cases of platform dependant integers
        if storage_type == 'MachineUInt' && value == ULONG_MAX
            # We assume NSUIntegerMax
            return 'Bro.IS_32BIT ? 0xffffffffL : 0xffffffffffffffffL'
        elsif storage_type == 'MachineSInt' && value == LONG_MAX
            # We assume NSIntegerMax
            return 'Bro.IS_32BIT ? Integer.MAX_VALUE : Long.MAX_VALUE'
        elsif storage_type == 'MachineSInt' && value == LONG_MIN
            # We assume NSIntegerMin
            return 'Bro.IS_32BIT ? Integer.MIN_VALUE : Long.MIN_VALUE'
        end

        # get data
        if value > LONG_MAX
            # ulong case, can't represent it in natural form in java, have to convert into hex
            return '0x'+ value.to_s(16) + 'L'
        end

        return value.to_s() + 'L'
    end


    def validate_custom_marshaler(model, enum, enum_storage_type, marshaler, marshaler_storage_type)
        # if there is typedef mapping to enum that matches same name, probably it is done with NS_ENUM and
        # in this case we don't need any marshaller
        java_name = enum.java_name
        enum_typedef = model.typedefs.find { |e| e.name == enum.name }
        if enum_typedef && enum_typedef.typedef_type.spelling == "enum #{enum.name}"
            $stderr.puts "\n\nWARN: Probably enum '#{enum.name}' is defined with 'typedef NS_ENUM/NS_OPTIONS' and not required marshaler"
        end

        if !marshaler_storage_type
            $stderr.puts "\n\nWARN: Failed to resolve enum storage type for '#{marshaler}' marshaller in enum '#{enum.name}', use `marshaler_storage_type` to specify one"
        elsif marshaler_storage_type != enum_storage_type
            machine_sized_marshaler = false
            machine_sized_marshaler = true if marshaler_storage_type  =~ /^Machine(.)Int$/
            machine_sized_storage_type = false
            machine_sized_storage_type = true if enum_storage_type =~ /^Machine(.)Int$/
            if machine_sized_marshaler != machine_sized_storage_type
                #
                # customs marshalers are used to override enum data type, but there is a common pitfall
                # when machine size int marshaler is used for stable int size enume (e.g. NSInteger marshaler for int enum)
                #
                if machine_sized_marshaler
                    $stderr.puts "\n\nWARN: enum '#{enum.name}' marshaler '#{marshaler}' is machine size int while enum storage type '#{enum_storage_type}' is not"
                else
                    $stderr.puts "\n\nWARN: enum '#{enum.name}' marshaler '#{marshaler}' is not machine size int while enum storage type '#{enum_storage_type}' is"
                end
            end
        else
            $stderr.puts "\n\nWARN: marshaller for '#{enum.name}' is not required as matches existing type '#{enum_storage_type}'"
        end
    end

    potential_constant_enums = []
    model.enums.each do |enum|
        next if !enum.is_available? || enum.is_outdated?
        c = model.get_enum_conf(enum.name)
        if c && !c['exclude'] && !c['transitive']
            data = {}
            java_name = enum.java_name
            bits = enum.is_options? || c['bits']
            ignore = c['ignore']
            data['name'] = java_name

            # handle marshalers
            marshaler = nil
            enum_storage_type = enum.raw_storage_type
            if c['marshaler']
                # configured marshaler
                marshaler = c['marshaler']
                marshaler_storage_type = c['marshaler_storage_type'] || enum_storage_type_from_marshaler(c['marshaler'])
                validate_custom_marshaler(model, enum, enum_storage_type, marshaler, marshaler_storage_type)
                enum_storage_type = marshaler_storage_type
            else
                # attaching marshaler to fit storage type

                if bits
                    # always convert storage type to same width unsigned
                    if enum_storage_type.start_with?('signed ')
                        enum_storage_type = 'un' + enum_storage_type;
                    elsif enum_storage_type == 'MachineSInt'
                        enum_storage_type = 'MachineUInt'
                    end

                    # default marshaler for bits is unsinged int
                    if enum_storage_type != "unsigned int"
                        marshaler = enum_marshaler_from_storrage_type(enum_storage_type, bits)                        
                        raise "Failed to resolve marshaller for enum storage type for '#{enum_storage_type}' in enum '#{enum.name}', use `marshaler' and 'marshaler_storage_type` to specify one" unless marshaler
                    end
                else
                    # default marshaler is ValuedEnum.AsSignedIntMarshaler.class as it attached to ValuedEnum
                    # it is not completely true as clang has unsigned int as default storage type.
                    # will try to fit values into signed int just to not attach marshaller
                    if enum_storage_type == "unsigned int" && enum.values.all?{ |e| e.raw_value >= 0 && e.raw_value <= INT_MAX}
                        enum_storage_type = "signed int"
                    end

                    # special case: as OSStatus is defined to be object in corefoundation we can't get its 
                    # underlying storage type (which is sint32)
                    if enum_storage_type == 'OSStatus'
                        enum_storage_type = "signed int"
                    end

                    # get the marshaller for storage type but, this is not required for enum in case of int type
                    if enum_storage_type != "signed int"
                        marshaler = enum_marshaler_from_storrage_type(enum_storage_type, bits)
                        raise "Failed to resolve marshaller for enum storage type for '#{enum_storage_type}' in enum '#{enum.name}', use `marshaler' and 'marshaler_storage_type` to specify one" unless marshaler
                    end
                end
            end

            # produce values
            if bits
                values = enum.values.find_all { |e| (!ignore || !e.name.match(ignore)) && !e.is_outdated? && e.is_available? }.map do |e|
                    value = enum_normalize_unsigned(e.raw_value, enum.raw_storage_type)
                    java_value = enum_entry_java_value(value, enum_storage_type)
                    model.push_availability(e).push("public static final #{java_name} #{e.java_name} = new #{java_name}(#{java_value})").join("\n    ")
                end.join(";\n    ") + ';'
                if !c['skip_none'] && !enum.values.find { |e| e.java_name == 'None' }
                    values = "public static final #{java_name} None = new #{java_name}(0L);\n    #{values}"
                end
            else
                values = enum.values.find_all { |e| (!ignore || !e.name.match(ignore)) && !e.is_outdated? && e.is_available? }.map do |e|
                    value = enum_normalize_unsigned(e.raw_value, enum.raw_storage_type)
                    java_value = enum_entry_java_value(value, enum_storage_type)
                    model.push_availability(e).push("#{e.java_name}(#{java_value})").join("\n    ")
                end.join(",\n    ") + ';'
            end

            data['values'] = "\n    #{values}\n    "
            data['annotations'] = (data['annotations'] || []).push("@Marshaler(#{marshaler}.class)") if marshaler
            data['imports'] = (data['imports'] || [].concat(imports))
            availability_annotations = []
            data['javadoc'] = "\n" + model.push_availability(enum, annotation_lines: availability_annotations).join("\n") + "\n"
            data['annotations'] = (data['annotations'] || []).concat(availability_annotations) if !availability_annotations.empty?
            data['template'] = bits ? def_bits_template : (c['nserror'] == true ? def_nserror_enum_template : def_enum_template)
            template_datas[java_name] = data
        #      merge_template(target_dir, package, java_name, bits ? def_bits_template : def_enum_template, data)
        elsif model.is_included?(enum) && (!c || !c['exclude'])
            # save to potential new entry
            add_potential_new_entry(enum, nil)

            # Possibly an enum with values that should be turned into constants
            potential_constant_enums.push(enum)
            $stderr.puts "WARN: Turning the enum #{enum.name} with first value #{enum.values[0].name} into constants" unless enum.name == ''
        end
    end

    model.structs.find_all { |e| !e.name.empty? }.each do |struct|
        c = model.get_class_conf(struct.name)
        # save to potential new entry
        add_potential_new_entry(struct, nil) if !c && model.is_included?(struct) && !struct.is_outdated?

        if c && !c['exclude'] && !c['transitive'] && !struct.is_outdated?
            name = c['name'] || struct.name
            template_datas[name] = struct.is_opaque? ? opaque_to_java(model, {}, name, c) : struct_to_java(model, {}, name, struct, c)
        end
    end
    model.typedefs.each do |td|
        c = model.get_class_conf(td.name)

        # save to potential new entry
        add_potential_new_entry(td, nil) if !c && td.struct && model.is_included?(td) && !td.is_outdated?

        next unless c && !c['exclude'] && !c['transitive']
        struct = td.struct
        if struct && struct.is_opaque?
            struct = model.structs.find { |e| e.name == td.struct.name } || td.struct
        end

        name = c['name'] || td.name
        template_datas[name] = !struct || struct.is_opaque? ? opaque_to_java(model, {}, name, c) : struct_to_java(model, {}, name, struct, c)
    end

    # Assign global values to classes
    values = {}
    model.global_values.find_all { |v| v.is_available? && !v.is_outdated? }.each do |v|
        vconf = v.conf
        if vconf && !vconf['exclude'] && !vconf['transitive']
            owner = vconf['class'] || default_class
            values[owner] = (values[owner] || []).push([v, vconf])
        end
    end

    # Generate template data for global values
    values.each do |owner, vals|
        data = template_datas[owner] || {}
        data['name'] = owner

        last_static_class = nil
        # making sort stable
        vals = vals.sort_by.with_index { |v_vconf, idx| [v_vconf[1]['static_class'] || "", idx]}

        methods_s = vals.map do |(v, vconf)|
            lines = []
            java_name = v.java_name()
            java_type = vconf['type'] || model.to_java_type(model.resolve_type(nil, v.type, true))
            visibility = vconf['visibility'] || 'public'
            marshaler = vconf['marshaler'] ? "@org.robovm.rt.bro.annotation.Marshaler(#{vconf['marshaler']}.class) " : ''

            # static class grouping support
            if last_static_class != vconf['static_class']
                unless last_static_class.nil?
                    # End last static class.
                    lines.push("}\n")
                end

                # Start new static class.
                last_static_class = vconf['static_class']

                lines.push("@Library(#{$library})", "public static class #{last_static_class} {", "    static { Bro.bind(#{last_static_class}.class); }\n")
            end
            indentation = last_static_class.nil? ? '' : '    '

            model.push_availability(v, lines, indentation)
            if vconf.key?('dereference') && !vconf['dereference']
                lines.push("#{indentation}@GlobalValue(symbol=\"#{v.name}\", optional=true, dereference=false)")
            else
                lines.push("#{indentation}@GlobalValue(symbol=\"#{v.name}\", optional=true)")
            end
            lines.push("#{indentation}#{visibility} static native #{marshaler}#{java_type} #{java_name}();")
            if !v.is_const? && !vconf['readonly']
                model.push_availability(v, lines, indentation)
                lines += ["#{indentation}@GlobalValue(symbol=\"#{v.name}\", optional=true)", "public static native void #{java_name}(#{marshaler}#{java_type} v);"]
            end
            lines
        end.flatten.join("\n    ")

        methods_s += "\n    }" unless last_static_class.nil?

        data['methods'] = (data['methods'] || '') + "\n    #{methods_s}\n    "
        data['imports'] = (data['imports'] || [].concat(imports))
        data['annotations'] = (data['annotations'] || []).push("@Library(#{$library})")
        data['bind'] = "static { Bro.bind(#{owner}.class); }"
        template_datas[owner] = data
    end

    def generate_global_value_enum_marshalers(lines, class_name, java_type)
        java_type = java_type.split(' ').last
        toObjectValueAppendix = ''
        toNativeValueText = 'o.value()'
        if java_type.include?('int') || java_type.include?('double')
            toObjectValueAppendix = ".#{java_type}Value()"
            toNativeValueText = 'NSNumber.valueOf(o.value())'
            java_type = 'NSNumber'
        end

        case java_type
        when 'CFType', 'CFString', 'CFNumber'
            base_type = 'CFType'
        when 'CGRect', 'CGSize'
            base_type = 'Struct'
        else
            base_type = 'NSObject'
        end

        lines.push('public static class Marshaler {')
        lines.push('    @MarshalsPointer')
        lines.push("    public static #{class_name} toObject(Class<#{class_name}> cls, long handle, long flags) {")
        lines.push("        #{java_type} o = (#{java_type}) #{base_type}.Marshaler.toObject(#{java_type}.class, handle, flags);")
        lines.push('        if (o == null) {')
        lines.push('            return null;')
        lines.push('        }')
        lines.push("        return #{class_name}.valueOf(o#{toObjectValueAppendix});")
        lines.push('    }')
        lines.push('    @MarshalsPointer')
        lines.push("    public static long toNative(#{class_name} o, long flags) {")
        lines.push('        if (o == null) {')
        lines.push('            return 0L;')
        lines.push('        }')
        lines.push("        return #{base_type}.Marshaler.toNative(#{toNativeValueText}, flags);")
        lines.push('    }')
        lines.push('}')

        return lines if base_type == 'Struct'

        lines.push('public static class AsListMarshaler {')
        lines.push('    @SuppressWarnings("unchecked")') if base_type == 'NSObject'
        lines.push('    @MarshalsPointer')
        lines.push("    public static List<#{class_name}> toObject(Class<? extends #{base_type}> cls, long handle, long flags) {")
        if base_type == 'NSObject'
            lines.push("        NSArray<#{java_type}> o = (NSArray<#{java_type}>) NSObject.Marshaler.toObject(NSArray.class, handle, flags);")
        else
            lines.push('        CFArray o = (CFArray) CFType.Marshaler.toObject(CFArray.class, handle, flags);')
        end
        lines.push('        if (o == null) {')
        lines.push('            return null;')
        lines.push('        }')
        lines.push("        List<#{class_name}> list = new ArrayList<>();")
        lines.push('        for (int i = 0; i < o.size(); i++) {')
        if base_type == 'NSObject'
            lines.push("            list.add(#{class_name}.valueOf(o.get(i)#{toObjectValueAppendix}));")
        else
            lines.push("            list.add(#{class_name}.valueOf(o.get(i, #{java_type}.class)#{toObjectValueAppendix}));")
        end
        lines.push('        }')
        lines.push('        return list;')
        lines.push('    }')
        lines.push('    @MarshalsPointer')
        lines.push("    public static long toNative(List<#{class_name}> l, long flags) {")
        lines.push('        if (l == null) {')
        lines.push('            return 0L;')
        lines.push('        }')
        if base_type == 'NSObject'
            lines.push("        NSArray<#{java_type}> array = new NSMutableArray<>();")
        else
            lines.push('        CFArray array = CFMutableArray.create();')
        end
        lines.push("        for (#{class_name} o : l) {")
        lines.push("            array.add(#{toNativeValueText});")
        lines.push('        }')
        lines.push("        return #{base_type}.Marshaler.toNative(array, flags);")
        lines.push('    }')
        lines.push('}')

        lines
    end

    # Generate template data for global value enumerations
    model.global_value_enums.each do |name, e|
        data = template_datas[name] || {}
        data['name'] = name
        data['type'] = e.java_type

        marshaler_lines = []
        generate_global_value_enum_marshalers(marshaler_lines, name, e.java_type)

        marshalers_s = marshaler_lines.flatten.join("\n    ")

        names = []
        vlines = []
        clines = []
        indentation = '    '

        e.values.sort_by { |v| v.since || 0.0 }

        e.values.find_all { |v| v.is_available? && !v.is_outdated? }.each do |v|
            vconf = v.conf

            java_name = v.java_name()

            names.push(java_name)
            java_type = vconf['type'] || model.to_java_type(model.resolve_type(e, v.type, true))
            java_type = 'int' if java_type == 'Integer'
            visibility = vconf['visibility'] || 'public'

            model.push_availability(v, vlines, indentation)
            if vconf.key?('dereference') && !vconf['dereference']
                vlines.push("#{indentation}@GlobalValue(symbol=\"#{v.name}\", optional=true, dereference=false)")
            else
                vlines.push("#{indentation}@GlobalValue(symbol=\"#{v.name}\", optional=true)")
            end
            vlines.push("#{indentation}#{visibility} static native #{java_type} #{java_name}();")

            model.push_availability(v, clines)
            clines.push("public static final #{name} #{java_name} = new #{name}(\"#{java_name}\");")
        end

        values_s = vlines.flatten.join("\n    ")
        constants_s = clines.flatten.join("\n    ")
        value_list_s = names.flatten.join(', ')

        java_type_no_anno = e.java_type.split(' ').last

        case java_type_no_anno
        when 'byte', 'short', 'long', 'float', 'double'
            java_type_no_anno = java_type_no_anno[0, 1].upcase + java_type_no_anno[1..-1]
        when 'int'
            java_type_no_anno = 'Integer'
        end

        data['marshalers'] = "\n    #{marshalers_s}\n    "
        data['values'] = "\n    #{values_s}\n        "
        data['constants'] = "\n    #{constants_s}\n    "
        data['extends'] = e.extends || "GlobalValueEnumeration<#{java_type_no_anno}>"
        data['imports'] = (data['imports'] || [].concat(imports))
        data['value_list'] = value_list_s
        data['annotations'] = (data['annotations'] || []).push("@Library(#{$library})").push('@StronglyLinked')

        data['template'] = def_value_enum_template
        template_datas[name] = data
    end

    # Generate template data for global value dictionary wrappers
    model.global_value_dictionaries.each do |name, d|
        data = template_datas[name] || {}
        d.generate_template_data(data)

        data['imports'] = (data['imports'] || [].concat(imports))
        data['template'] = def_value_dictionary_template

        template_datas[name] = data
    end

    # Assign functions to classes
    functions = {}
    model.functions.find_all { |f| f.is_available? && !f.is_outdated? }.each do |f|
        fconf = model.get_function_conf(f.name)
        if fconf 
            next if fconf['exclude']
            if f.is_inline? && !$dbg_dump_inline_fn
                # function expected but it was converted to inline/static and it will not be found during runtime, showing ERR 
                $stderr.puts ""
                $stderr.puts "ERROR: Expected function '#{f.name}' now 'inline', probably manual implementation is expected! (location #{Bro.location_to_s(f.location)})"
                $stderr.puts ""
                next
            end

            owner = fconf['class'] || default_class
            functions[owner] = (functions[owner] || []).push([f, fconf])
        elsif f.is_inline?
            $stderr.puts "WARN: Ignoring 'inline' function '#{f.name}' at #{Bro.location_to_s(f.location)}"
        end
    end

    # Generate template data for functions
    functions.each do |owner, funcs|
        data = template_datas[owner] || {}
        data['name'] = owner
        methods_lines = [] 
        constructors_lines = [] 

        # proceed not inline functions (these shall not here if not forced by env variable )
        funcs.find_all {|f, fconf| !f.is_inline?}.each do |(f, fconf)|
            name = fconf['name'] || f.name
            name = name[0, 1].downcase + name[1..-1] # todo: have force name downcase as there is bunch of yamls to be changed otherwise
            lines = []
            constructor_lines = [] 
            visibility = fconf['visibility'] || 'public'
            parameters = f.parameters
            params_conf = fconf['parameters'] || {}
            annotations = fconf['annotations'] && !fconf['annotations'].empty? ? fconf['annotations'].uniq.join(' ') : nil
            static = 'static '
            use_wrapper = false # mean there is @ByVal, constructor or throw wrapper to be generated 
            constructor = false # wraping constructor 
            firstparamtype = if parameters.size >= 1 then (params_conf[parameters[0].name] || {})['type'] || model.resolve_type(nil, parameters[0].type).java_name else nil end
            ret_type = fconf['return_type'] || model.to_java_type(model.resolve_type(nil, f.return_type))
            if fconf['constructor'] == true && ret_type == owner
                # wrapping into constructor, leaving static bridge 
                use_wrapper = true
            	constructor = true
            elsif !fconf['static'] && (firstparamtype == owner || firstparamtype == "@ByVal #{owner}")
                # re-resolve with annotations
                firstparamtype = (params_conf[parameters[0].name] || {})['type'] ||  model.to_java_type(model.resolve_type(nil, parameters[0].type))
                if firstparamtype.start_with?('@ByVal')
                    # If the instance is passed @ByVal we need to make a wrapper method and keep the @Bridge method static
                    use_wrapper = true
                else 
                    # Instance method
                    static = ''
                    parameters = parameters[1..-1]
                end
            end

            if fconf['throws']
                # there going to be wrapper, also remove pointer to error from wrapper params 
                use_wrapper = true
            end

            # types for bridge with native annotations (@ByVal, Marshallers etc )
			bridge_param_types = parameters.each_with_object([]) do |p, l|
				pconf = params_conf[p.name] || params_conf[l.size] || {}
				marshaler = pconf['marshaler'] ? "@org.robovm.rt.bro.annotation.Marshaler(#{pconf['marshaler']}.class) " : ''
				l.push([marshaler, "#{pconf['type'] || model.to_java_type(model.resolve_type(nil, p.type))}", pconf['name'] || p.name])
				l
            end
            bridge_ret_type = fconf['return_type'] || model.to_java_type(model.resolve_type(nil, f.return_type))
            
            if use_wrapper
                # types for wrapper, without marshallers
                param_types = parameters.each_with_object([]) do |p, l|
                    pconf = params_conf[p.name] || params_conf[l.size] || {}
                    l.push(["#{pconf['type'] || model.to_wrapper_java_type(model.resolve_type(nil, p.type))}", pconf['name'] || p.name])
                    l
                end
                ret_type = fconf['return_type'] || model.resolve_type(nil, f.return_type).java_name

                if fconf['throws']
                    error_type = 'NSError'
                    case fconf['throws']
                    when 'CFStreamErrorException'
                        error_type = 'CFStreamError'
                    end

                    throw_parameters_s = param_types[0..-2].map { |p| "#{p[0]} #{p[1]}" }.join(', ')
                    throw_args_s = (param_types[0..-2].map {|p| p[1] } + ['ptr']).join(', ')

                    if constructor 
                        model.push_availability(f, constructor_lines)
                        constructor_lines << annotations.to_s if annotations
                        constructor_lines << "#{visibility} #{owner}(#{throw_parameters_s}) throws #{fconf['throws']} {"
                        constructor_lines << "   super((SkipInit) null);"
                        constructor_lines << "   #{error_type}.#{error_type}Ptr ptr = new #{error_type}.#{error_type}Ptr();"
                        constructor_lines << "   long handle = #{name}(#{throw_args_s});"
                        constructor_lines << "   if (ptr.get() != null) { throw new #{fconf['throws']}(ptr.get()); }"
                        constructor_lines << "   initObject(handle);"
                        constructor_lines << '}'
                        bridge_ret_type = "@Pointer long" unless conf['return_type']
                    else 
                        model.push_availability(f, lines)
                        lines << annotations.to_s if annotations
                        lines << "#{visibility} #{static}#{ret_type} #{name}(#{throw_parameters_s}) throws #{fconf['throws']} {"
                        lines << "   #{error_type}.#{error_type}Ptr ptr = new #{error_type}.#{error_type}Ptr();"
                        ret = ret_type.gsub(/@\w+ /, '') # Trim annotations
                        ret = ret == 'void' ? '' : "#{ret} result = "
                        lines << "   #{ret}#{name}(#{throw_args_s});"
                        lines << "   if (ptr.get() != null) { throw new #{fconf['throws']}(ptr.get()); }"
                        lines << '   return result;' if ret_type != 'void'
                        lines << '}'
                    end

                    # TODO: mutate parameter to @Brige to be NSError
                    bridge_param_types[-1] = ["", "#{error_type}.#{error_type}Ptr", "error"]
                else 
                    if (constructor) 
                        parameters_s = param_types.map { |p| "#{p[0]} #{p[1]}" }.join(', ')
                        args_s = param_types.map {|p| p[1] }.join(', ')
                        should_retain = fconf['constructor_retain'] || false
                        model.push_availability(f, constructor_lines)
                        constructor_lines << annotations.to_s if annotations
                        constructor_lines << "#{visibility} #{owner}(#{parameters_s}) { super((Handle) null, #{name}(#{args_s})); #{should_retain ? "retain(getHandle());" : ""} }"
                        bridge_ret_type = "@Pointer long" unless conf['return_type']
                    else 
                        # instance wrapper arround saved static method (due @ByVal)
                        parameters_s = param_types[1..-1].map { |p| "#{p[0]} #{p[1]}" }.join(', ')
                        model.push_availability(f, lines)
                        args_s = (["this"] + param_types[1..-1].map {|p| p[1] }).join(', ')
                        lines << "#{visibility} #{ret_type} #{name}(#{parameters_s}) { #{ret_type != 'void' ? 'return ' : ''}#{name}(#{args_s}); }"
                    end
                end
                # for wrapper @Bridge visibility is private 
                visibility = 'private'
            end

            parameters_full_s = bridge_param_types.map {|p| "#{p[0]}#{p[1]} #{p[2]}"}.join(', ')
        	ret_marshaler = fconf['return_marshaler'] ? "@org.robovm.rt.bro.annotation.Marshaler(#{fconf['return_marshaler']}.class) " : ''

            # bridge method
            model.push_availability(f, lines)
            lines << annotations.to_s if annotations
            lines << "@Bridge(symbol=\"#{f.name}\", optional=true)"
            lines << "#{visibility} #{static}native #{ret_marshaler}#{bridge_ret_type} #{name}(#{parameters_full_s});"

            methods_lines.concat(lines)
            constructors_lines.concat(constructor_lines)
        end

        # dump all inline functions 
        funcs.find_all {|f, fconf| f.is_inline? && f.inline_statement != nil}.each do |(f, fconf)|
            name = fconf['name'] || f.name
            name = name[0, 1].downcase + name[1..-1] # todo: have force name downcase as there is bunch of yamls to be changed otherwise 
            lines = []
            parameters = f.parameters
            params_conf = fconf['parameters'] || {}
            annotations = fconf['annotations'] && !fconf['annotations'].empty? ? fconf['annotations'].uniq.join(' ') : nil
            ret_type = fconf['return_type'] || model.to_java_type(model.resolve_type(nil, f.return_type))
            param_types = parameters.each_with_object([]) do |p, l|
                pconf = params_conf[p.name] || params_conf[l.size] || {}
                l.push(["#{pconf['type'] || model.resolve_type(nil, p.type).java_name}", pconf['name'] || p.name])
                l
            end
            parameters_s = param_types.map { |p| "#{p[0]} #{p[1]}" }.join(', ')
            lines << "/**"
            lines << " * ported from #{f.name}"
            lines << "*/"
            lines << "public static #{ret_type} #{name}(#{parameters_s}) {"
            f.inline_statement.split("\n").each {|l| lines << "  // " + l}                
            if ret_type != 'void'
                default_value = model.default_value_for_type(ret_type)
                lines << "  return #{default_value};"
            end
            lines << "}"
            methods_lines.concat(lines)
        end

        methods_s = methods_lines.flatten.join("\n    ")
        constructors_s = constructors_lines.flatten.join("\n    ")
        data['methods'] = (data['methods'] || '') + "\n    #{methods_s}\n    "
        data['constructors'] = (data['constructors'] || '') + "\n    #{constructors_s}\n    " unless constructors_s.empty?
        data['imports'] = (data['imports'] || [].concat(imports))
        data['annotations'] = (data['annotations'] || []).push("@Library(#{$library})")
        data['bind'] = "static { Bro.bind(#{owner}.class); }"
        template_datas[owner] = data
    end

    # Assign constants to classes
    constants = {}
    model.constant_values.each do |v|
        vconf = model.get_constant_conf(v.name)
        if vconf && !vconf['exclude'] && !vconf['transitive']
            owner = vconf['class'] || default_class
            constants[owner] = (constants[owner] || []).push([v, vconf])
        end
    end
    # Create ConstantValues for values in remaining enums
    potential_constant_enums.each do |enum|
        type = enum.java_enum_type.java_name =~ /\blong$/ ? 'long' : 'int'
        enum.type.declaration.visit_children do |cursor, _parent|
            case cursor.kind
            when :cursor_enum_constant_decl
                e = Bro::EnumValue.new model, cursor, enum
                if e.is_available?
                    name = e.name
                    value = e.raw_value
                    value = "#{value}L" if type == 'long'
                    c = model.get_constant_conf(name)
                    if c && !c['exclude']
                        owner = c['class'] || default_class
                        v = Bro::ConstantValue.new model, cursor, value, type
                        constants[owner] = (constants[owner] || []).push([v, c])
                    end
                end
            end
            next :continue
        end
    end

    # Generate template data for constants
    constants.each do |owner, vals|
        data = template_datas[owner] || {}
        data['name'] = owner

        last_static_class = nil
        # making sort stable
        vals = vals.sort_by.with_index { |v_vconf, idx| [v_vconf[1]['static_class'] || "", idx]}


        constants_s = vals.map do |(v, vconf)|
            lines = []
            name = vconf['name'] || v.name
            # TODO: Determine type more intelligently?
            visibility = vconf['visibility'] || 'public'
            java_type = vconf['type'] || v.type || 'double'

            # static class grouping support
            if last_static_class != vconf['static_class']
                unless last_static_class.nil?
                    # End last static class.
                    lines.push("}\n")
                end

                # Start new static class.
                last_static_class = vconf['static_class']

                lines.push("public static class #{last_static_class} {")
            end
            indentation = last_static_class.nil? ? '' : '    '

            lines += ["#{indentation}#{visibility} static final #{java_type} #{name} = #{v.value};"]
            lines
        end.flatten.join("\n    ")

        constants_s += "\n    }" unless last_static_class.nil?

        data['constants'] = (data['constants'] || '') + "\n    #{constants_s}\n    "
        data['imports'] = (data['imports'] || [].concat(imports))
        template_datas[owner] = data
    end


    # returns inherited initializer.
    # as these has to be turned into constructor in target classes
    # also availability attribute allows controlling if these has to be
    # added
    def inherited_initializers(model, owner, conf)
        def g(model, owner, cls, conf, seen)
            r = []
            return r if !cls.is_a?(Bro::ObjCClass) || conf["exclude"] == true

            inits = []
            methods_conf = conf['methods'] || {}
            cls.instance_methods.each do |method|
                full_name = (method.is_a?(Bro::ObjCClassMethod) ? '+' : '-') + method.name

                next unless is_init?(owner, method) && !seen[full_name]
                seen[full_name] = true

                if owner != cls
                    # skip if method is marked not constructor
                    mconf = methods_conf[full_name]
                    inits.push(method) unless mconf && mconf["exclude"] != true && mconf["constructor"] == false
                end
            end

            r.push([inits, { "methods" => methods_conf, "inherited_initializers" => true }, cls]) if inits.length > 0
            if cls.superclass
                supercls = model.objc_classes.find { |e| e.name == cls.superclass }
                super_conf = model.get_class_conf(supercls.name)
                r += g(model, owner, supercls, super_conf, seen) if super_conf != nil
            end
            r
        end

        g(model, owner, owner, conf, {})
    end

    # returns inherited class(static) methods/properties .
    def inherited_static_items(model, owner, conf)
        def g(model, owner, cls, conf, seen, seen_props)
            r = []
            return r if !cls.is_a?(Bro::ObjCClass) || conf["exclude"] == true

            # duplicate static methods from
            statics = []
            methods_conf = conf['methods'] || {}
            cls.class_methods.find_all { |method| method.is_a?(Bro::ObjCClassMethod) }.each do |method|
                full_name = '+' + method.name
                next if seen[full_name]
                seen[full_name] = true

                if owner != cls
                    mconf = methods_conf[full_name]
                    statics.push(method) unless mconf && (mconf["exclude"] == true || mconf["constructor"] == true)
                end
            end
            # duplicate static properties
            props_conf = conf['properties'] || {}
            cls.properties.find_all { |prop| prop.is_static?}.each do |prop|
                full_name = '+' + prop.name
                next if seen_props[full_name]
                seen_props[full_name] = true

                if owner != cls
                    pconf = props_conf[full_name]
                    statics.push(prop) unless pconf && pconf["exclude"] == true
                end
            end
            r.push([statics, conf, cls]) if statics.length > 0

            if cls.superclass
                supercls = model.objc_classes.find { |e| e.name == cls.superclass }
                super_conf = model.get_class_conf(supercls.name)
                r += g(model, owner, supercls, super_conf, seen, seen_props) if super_conf != nil
            end
            r
        end

        g(model, owner, owner, conf, {}, {})
    end


    # Assign methods and properties to classes/protocols
    members = {}
    (model.objc_classes + model.objc_protocols).each do |cls|
        c = cls.is_a?(Bro::ObjCClass) ? model.get_class_conf(cls.name) : model.get_protocol_conf(cls.name)
        # before skipping check if this is potentialy missing class or protocol from yaml file
        add_potential_new_entry(cls, nil) if !c && cls.is_available? && !cls.is_opaque? && !cls.is_outdated? && model.is_included?(cls)

        next unless c && !c['exclude'] && !c['transitive'] && cls.is_available? && !cls.is_outdated?
        owner = c['name'] || cls.java_name
        members[owner] = members[owner] || { owner: cls, owner_name: owner, members: [], conf: c }
        members[owner][:members].push([cls.instance_methods + cls.class_methods + cls.properties, c, cls])
    end

    # add initializers/static items from super classes if these are missing
    model.objc_classes.each do |cls|
        c = model.get_class_conf(cls.name)
        next unless c && !c['exclude'] && !c['transitive'] && cls.is_available? && !cls.is_outdated?
        owner = c['name'] || cls.java_name

        # add inits from inherited classses
        # otherwise class will lack possible constructors
        inheriter_inits = inherited_initializers(model, cls, c)
        members[owner][:members] += inheriter_inits

        inheriter_static = inherited_static_items(model, cls, c)
        members[owner][:members] += inheriter_static
    end

    unassigned_categories = []
    model.objc_categories.each do |cat|
        # skip category if exactly specified
        exact_c = c = model.get_category_conf("#{cat.name}@#{cat.owner}")
        next if exact_c && exact_c['exclude'] == true

        c = exact_c || model.get_category_conf(cat.name)
        owner_name = c && c['owner'] || cat.owner
        owner_cls = model.objc_classes.find { |e| e.name == owner_name }
        owner = nil
        if owner_cls
            owner_conf = model.get_class_conf(owner_cls.name)
            if owner_conf && !owner_conf['exclude'] && owner_cls.is_available? && !owner_cls.is_outdated?
                if !owner_conf['transitive']
                    owner = owner_conf['name'] || owner_cls.java_name
                    members[owner] = members[owner] || { owner: owner_cls, owner_name: owner, members: [], conf: owner_conf }
                    members[owner][:members].push([cat.instance_methods + cat.class_methods + cat.properties, owner_conf, owner_cls])
                end
                owner_cls.protocols = owner_cls.protocols + cat.protocols
                owner_cls.instance_methods = owner_cls.instance_methods + cat.instance_methods
                owner_cls.class_methods = owner_cls.class_methods + cat.class_methods
                owner_cls.properties = owner_cls.properties + cat.properties
            end
        end
        unassigned_categories.push(cat) if !owner && model.is_included?(cat)
    end
    unassigned_categories.each do |cat|
        c = model.get_category_conf("#{cat.name}@#{cat.owner}")
        c = model.get_category_conf(cat.name) unless c
        c = model.get_category_conf(cat.owner) unless c
        if c && !c['exclude'] && !c['transitive']
            owner = c['name'] || cat.java_name
            members[owner] = members[owner] || { owner: cat, owner_name: owner, members: [], conf: c }
            members[owner][:members].push([cat.instance_methods + cat.class_methods + cat.properties, c, cat])
        elsif !c || (!c['exclude'] && !c['transitive'])
            $stderr.puts "WARN: Skipping category #{cat.name} for #{cat.owner}"
        end
    end

    # also returns excluded when its required to check if method in class from protocol to be excluded  
    def all_protocols(model, cls, conf, include_excluded: false)
        def f(model, cls, conf, include_excluded)
            result = []
            return result if conf.nil?
            (conf['protocols'] || cls.protocols).each do |prot_name|
                prot = model.objc_protocols.find { |p| p.name == prot_name }
                protc = model.get_protocol_conf(prot.name) if prot
                if protc && !protc['skip_methods'] && (include_excluded || protc["exclude"] != true)
                    result.push([prot, protc])
                    result += f(model, prot, protc, include_excluded)
                end
            end
            result
        end

        def g(model, cls, conf, include_excluded)
            r = []
            if !cls.is_a?(Bro::ObjCProtocol) && cls.superclass
                supercls = model.objc_classes.find { |e| e.name == cls.superclass }
                super_conf = model.get_class_conf(supercls.name)
                r = g(model, supercls, super_conf, include_excluded)
            end
            r + f(model, cls, conf, include_excluded)
        end
        g(model, cls, conf, include_excluded).uniq { |e| e[0].name }
    end

    # returns inherited class(static) methods/properties from protocols.
    def all_static_from_protocols(model, prots)
        seen = {}
        seen_props = {}
        r = []
        prots.each do |(prot, protc)|
            # duplicate static methods from
            statics = []
            methods_conf = protc['methods'] || {}
            prot.class_methods.find_all { |method| method.is_a?(Bro::ObjCClassMethod) }.each do |method|
                full_name = '+' + method.name
                next if seen[full_name]
                seen[full_name] = true
                mconf = methods_conf[full_name]
                statics.push(method) unless mconf && (mconf["exclude"] == true || mconf["constructor"] == true)
            end

            # duplicate static properties
            props_conf = protc['properties'] || {}
            prot.properties.find_all { |prop| prop.is_static?}.each do |prop|
                full_name = '+' + prop.name
                next if seen_props[full_name]
                seen_props[full_name] = true
                pconf = props_conf[full_name]
                statics.push(prop) unless pconf && pconf["exclude"] == true
                r.push([statics, protc, prot]) if statics.length > 0
            end
        end
        r
    end

    # same as [prot.instance_methods + prot.class_methods + prot.properties, protc, prot]
    # but don't adds excluded methods
    def all_not_excluded(cls, prot, protc)
        methods_conf = protc['methods'] || {}
        props_conf = protc['properties'] || {}
        r = []

        (prot.instance_methods + prot.class_methods).each do |method|
            full_name = method.full_name
            mconf = methods_conf[full_name]
            r.push(method) unless mconf && mconf["exclude"] == true
        end
        prot.properties.each do |prop|
            full_name = prop.full_name
            pconf = props_conf[full_name]
            r.push(prop) unless pconf && pconf["exclude"] == true
        end

        r
    end

    # Add all methods defined by protocols to all implementing classes
    model.objc_classes.find_all { |cls| !cls.is_opaque? }.each do |cls|
        c = model.get_class_conf(cls.name)
        next unless c && !c['exclude'] && !c['transitive'] && cls.is_available? && !cls.is_outdated?

        owner = c['name'] || cls.java_name
        prots = all_protocols(model, cls, c)
        if cls.superclass
            parent_prots = all_protocols(model, model.objc_classes.find { |e| e.name == cls.superclass }, model.get_class_conf(cls.superclass))
            prots -= parent_prots
            parent_prots -= prots
        else
            parent_prots = nil
        end
        prots.each do |(prot, protc)|
            members[owner] = members[owner] || { owner: cls, owner_name: owner, members: [], conf: c }
            members[owner][:members].push([all_not_excluded(cls, prot, protc), protc, prot])
        end
        # add statics
        if parent_prots
            members[owner] = members[owner] || { owner: cls, owner_name: owner, members: [], conf: c }
            members[owner][:members] += all_static_from_protocols(model, parent_prots)
        end
    end

    # Add all methods defined by protocols to all implementing converted protocol classes
    model.objc_protocols.find_all do |cls|
        c = model.get_protocol_conf(cls.name)
        next unless c && !c['exclude'] && !c['transitive'] && c['class']
        owner = c['name'] || cls.java_name
        prots = all_protocols(model, cls, c)
        prots.each do |(prot, protc)|
            members[owner] = members[owner] || { owner: cls, owner_name: owner, members: [], conf: c }
            members[owner][:members].push([prot.instance_methods + prot.class_methods + prot.properties, protc, prot])
        end
    end

    def protocol_list(model, protocols, conf)
        l = []
        if conf['protocols']
            l = conf['protocols']
        else
            protocols.each do |name|
                c = model.get_protocol_conf(name)
                l.push(model.objc_protocols.find { |p| p.name == name }.java_name) if c && c['exclude'] != true && c['skip_implements'] != true
            end
        end
        l
    end

    # list all protocols including inherited ones. it is needed to create adapter in case there is several parent protocols
    def protocol_list_deep(model, protocols, conf, l = [])
        if conf['protocols']
            l += conf['protocols']
        else
            protocols.each do |name|
                c = model.get_protocol_conf(name)
                next unless c
                pr = model.objc_protocols.find { |p| p.name == name }
                next if !pr || l.include?(pr.java_name)
                l.push(pr.java_name)
                protocol_list_deep(model, pr.protocols, c, l)
            end
        end
        l
    end

    def protocol_list_s(model, keyword, protocols, conf)
        l = protocol_list(model, protocols, conf)
        l.empty? ? nil : (keyword + ' ' + l.join(', '))
    end

    model.objc_classes.find_all { |cls| !cls.is_opaque? } .each do |cls|
        c = model.get_class_conf(cls.name)
        if !c  && model.is_included?(cls) && cls.is_available? && !cls.is_outdated? && !cls.is_opaque?
            $stderr.puts "CONV: missing class #{cls.java_name}"
        end

        next unless c && !c['exclude'] && !c['transitive'] && cls.is_available? && !cls.is_outdated?
        name = c['name'] || cls.java_name
        runtime_name = cls.valueAttributeForKey("objc_runtime_name")
        runtime_name = "(\"#{runtime_name}\")" if runtime_name
        data = template_datas[name] || {}
        if cls.template_params.empty?
            data['name'] = name
            data['ptr'] = "public static class #{cls.java_name}Ptr extends Ptr<#{cls.java_name}, #{cls.java_name}Ptr> {}"
        else
            # add generic definitions from template params
            param_decl = "<" + cls.template_params.map{|e| "#{e.java_name}#{e.extend_java_type}"}.join(", ") + ">"
            param_list = "<" + cls.template_params.map{|e| e.java_name}.join(", ") + ">"
            data['name'] = name + param_decl
            data['ptr'] = "public static class #{cls.java_name}Ptr#{param_decl} extends Ptr<#{cls.java_name}#{param_list}, #{cls.java_name}Ptr#{param_list}> {}"
        end
        data['visibility'] = c['visibility'] || 'public'
        # resolve super_class -- skip ones that are marked as excluded
        def resolve_super(model, c)
            while (c && c.superclass)
                conf = model.conf_classes[c.superclass] || {}
                return conf['name'] || c.superclass if conf['exclude'] != true
                c = model.objc_classes.find{ |e| e.name == c.superclass}
            end
            'ObjCObject'
        end
        data['extends'] = c['extends'] || resolve_super(model, cls)
        # generics: adding template arguments to inherited class
        # FIXME: add option to super
        if cls.superclass && cls.super_template_args
            super_cls = model.objc_classes.find{ |e| e.name == cls.superclass}
            if super_cls && !super_cls.template_params.empty?
                template_args = model.resolve_template_params(cls, cls.super_template_args)
                if template_args && template_args.size == super_cls.template_params.size
                    data['extends'] = data['extends'] + "<" + template_args.map{|e| e.java_name}.join(", ") + ">"
                end
            end
        end
        data['imports'] = (data['imports'] || [].concat(imports))
        data['imports'] = data['imports'].concat(c['imports']) if c['imports']
        data['implements'] = protocol_list_s(model, 'implements', cls.protocols, c)
        data['annotations'] = (data['annotations'] || []).push("@Library(#{$library})").push("@NativeClass#{runtime_name}")
        data['bind'] = "static { ObjCRuntime.bind(#{name}.class); }"
        availability_annotations = []
        data['javadoc'] = "\n" + model.push_availability(cls, annotation_lines: availability_annotations).join("\n") + "\n"
        data['annotations'] = (data['annotations'] || []).concat(availability_annotations) if !availability_annotations.empty?
        template_datas[name] = data
    end

    model.objc_protocols.each do |prot|
        c = model.get_protocol_conf(prot.name)
        if !c  &&  model.is_included?(prot) && prot.is_available? && !prot.is_outdated? && !prot.is_opaque?
            $stderr.puts "CONV: missing protocol #{prot.java_name}"
        end
        next unless c && !c['exclude'] && !c['transitive'] && !prot.is_outdated?
        name = c['name'] || prot.java_name
        data = template_datas[name] || {}
        data['name'] = name
        data['visibility'] = c['visibility'] || 'public'
        if c['class']
            data['extends'] = c['extends'] || 'NSObject'
            data['implements'] = protocol_list_s(model, 'implements', prot.protocols, c)
            data['ptr'] = "public static class #{prot.java_name}Ptr extends Ptr<#{prot.java_name}, #{prot.java_name}Ptr> {}"
            data['annotations'] = (data['annotations'] || []).push("@Library(#{$library})")
            data['bind'] = "static { ObjCRuntime.bind(#{name}.class); }"
        else
            data['implements'] = protocol_list_s(model, 'extends', prot.protocols, c) || 'extends NSObjectProtocol'
            data['template'] = def_protocol_template
        end
        data['imports'] = (data['imports'] || [].concat(imports))
        data['imports'] = data['imports'].concat(c['imports']) if c['imports']
        availability_annotations = []
        data['javadoc'] = "\n" + model.push_availability(prot, annotation_lines: availability_annotations).join("\n") + "\n"
        data['annotations'] = (data['annotations'] || []).concat(availability_annotations) if !availability_annotations.empty?
        template_datas[name] = data
    end

    # Add methods/properties to protocol interface adapter classes
    members.values.each do |h|
        owner = h[:owner]
        next unless owner.is_a?(Bro::ObjCProtocol)
        c = model.get_protocol_conf(owner.name)
        next unless !c['skip_adapter'] && !c['class']
        interface_name = c['name'] || owner.java_name
        owner_name = interface_name + 'Adapter'
        methods_lines = []
        properties_lines = []

        # in case there is more than one protocol being inherited this addapter can't
        # inherit other adapters but has to implement all methods of all protocols it inherits
        prot_members = h[:members]
        protocols = protocol_list(model, owner.protocols, c).find_all { |e| e != 'NSObjectProtocol' }
        parent_adapter = nil
        # check for one that is sutable for adapter s
        protocols.each do |name|
            # check if adapter exists
            protc = model.get_protocol_conf(name)
            if protc && !protc['skip_adapter']
                parent_adapter = name
                break
            end
        end

        # refilter protocols
        protocols = protocols.find_all { |e| e != parent_adapter } if parent_adapter

        # adapter is not found has to implement everything event if there is only one protocol
        if protocols.length
            protocols_methods = []
            protocols_deep = protocol_list_deep(model, protocols, {}).find_all { |e| e != 'NSObjectProtocol' }
            protocols_deep.each do |name|
                protc = model.get_protocol_conf(name)
                prot = model.objc_protocols.find { |p| p.name == name } if protc
                next unless prot && protc

                if !parent_adapter && !protc['skip_adapter']
                    # use this protocol as adapter one
                    parent_adapter = prot.name
                else
                    # use this protocol to implement all methods
                    protocols_methods.push([prot.instance_methods + prot.class_methods + prot.properties, protc, prot])
                end
            end
            prot_members = prot_members + protocols_methods
        end


        prot_members.each do |(members, c, prot)|
            members.find_all { |m| m.is_a?(Bro::ObjCMethod) && m.is_available? }.each do |m|
                # resolve configuration for method
                full_name = (m.is_a?(Bro::ObjCClassMethod) ? '+' : '-') + m.name
                members_conf = c['methods'] || {}
                method_conf = model.get_conf_for_key(full_name, members_conf)
                a = method_to_java(model, owner_name, owner, prot, m, method_conf || {}, {}, true, c['class'])
                methods_lines.concat(a[0])
            end
            # TODO: temporaly don't add static properties to interfaces
            members.find_all { |m| m.is_a?(Bro::ObjCProperty) && m.is_available? && !(m.is_static? && owner.is_a?(Bro::ObjCProtocol))}.each do |p|
                properties_lines.concat(property_to_java(model, owner, p, c['properties'] || {}, {}, true))
            end
        end

        data = template_datas[owner_name] || {}
        data['name'] = owner_name
        data['extends'] = parent_adapter ? "#{parent_adapter}Adapter" : 'NSObject'
        data['implements'] = "implements #{interface_name}"
        methods_s = methods_lines.flatten.join("\n    ")
        data['methods'] = (data['methods'] || '') + "\n    #{methods_s}\n    "
        properties_s = properties_lines.flatten.join("\n    ")
        data['properties'] = (data['properties'] || '') + "\n    #{properties_s}\n    "
        template_datas[owner_name] = data
    end

    # resolves method or property configuration
    # owner             -- target class/protocol method goes to (method itself can be inherited from other protocol/class)
    # full_name         -- full method name
    # member_owner      -- class/protocol method was inherited from
    # bottom_limit      -- super class to stop resolution at (exclusive)
    # conf_key          -- key to find methods configuration. reserved for future use. e.g. in case properties to be resolved similar way
    # exact_match       -- specifies if configuration key shall match full name (no wildcards to be used), otherwise wildcards allowed
    # include_protocols -- true if configuration to be looked in adopted protocols as well
    def resolve_member_config(model, owner, member, member_owner: nil, bottom_limit: nil, conf_key: "methods", exact_match: false, include_protocols: false)
        full_name = member.full_name
        cls = owner
        cls_conf = model.get_class_conf(cls.name) if cls.is_a?(Bro::ObjCClass)
        cls_conf = model.get_protocol_conf(cls.name) if cls.is_a?(Bro::ObjCProtocol)
        member_owner ||= owner # in case not provided

        if bottom_limit == owner
            # special case for one shot resolve. e.g. to check only in owner
            # to make cycle break set owner to super, or null
            if owner.is_a?(Bro::ObjCClass) && owner.superclass
                bottom_limit = model.objc_classes.find { |e| e.name == owner.superclass }
            else
                bottom_limit = nil
            end
        end

        # walk from owner till member_owner(bottom_limit) (exclusive)
        while cls != nil && cls != bottom_limit && cls_conf != nil
            members_conf = cls_conf[conf_key] || {}
            if cls == owner
                pmembers_conf = cls_conf[conf_key + "_private"] || {}
                members_conf = members_conf.merge(pmembers_conf)
            end
            conf = nil
            if exact_match
                conf = members_conf[full_name]
                if conf == nil
                    # no exact match, perform pattern match for global scope overrides
                    conf = model.get_conf_for_key(full_name, members_conf)

                    # ignore pattern match if it is scope is not implicitly set to global ( so all init* will not be applied if not forced to be global)
                    # ignore scope rule in case config comes from member_owner (e.g. it config from method origin)
                    if cls != member_owner && conf && conf["scope"] != "global"
                        conf = nil
                    end
                end
            else
                # perform pattern match
                conf = model.get_conf_for_key(full_name, members_conf)

                # special case to drop pattern match result:
                # drop all "exclude" pattern match if it is scope is not implicitly set to global (otherwise any {'-.*' : {"exclude": true}} config will drop all methods)
                # ignore scope rule in case config comes from member_owner or owner (e.g. it config from method origin)
                if cls != member_owner && cls != owner && conf && conf["exclude"] == true && conf["scope"] != "global"
                    conf = nil
                end
            end


            return conf, cls if conf
            return {"exclude" => true} if cls_conf["exclude"] == true && cls == member_owner

            # switch to super
            super_cls = nil
            super_cls_conf = nil
            if cls.is_a?(Bro::ObjCClass) && cls.superclass != nil
                super_cls = model.objc_classes.find { |e| e.name == cls.superclass }
                super_cls_conf = model.get_class_conf(cls.superclass)
            end

            # check if there is a config in protocol this class implements
            if cls.is_a?(Bro::ObjCClass) && include_protocols
                prots = all_protocols(model, cls, cls_conf, include_excluded: true)
                prots -= all_protocols(model, super_cls, super_cls_conf, include_excluded: true) if super_cls && super_cls_conf
                prots.each do |(prot, protc)|
                    if prot.containsMember?(member)
                        members_conf = protc[conf_key] || {}
                        conf = model.get_conf_for_key(full_name, members_conf)
                        return conf, prot unless !conf || (conf['exclude'] == true && conf['scope'] != 'global' && prot != member_owner)
                        return {"exclude" => true} if protc["exclude"] == true
                    end
                end
            end

            cls = super_cls
            cls_conf = super_cls_conf
        end

        return nil, nil
    end

    members.values.each do |h|
        owner = h[:owner]
        owner_conf = h[:conf]
        owner_name = h[:owner_name]
        seen = {}
        methods_lines = []
        constructors_lines = []
        properties_lines = []
        has_def_constructor = false
        h[:members].each do |(members, members_conf, members_owner)|
            members.find_all { |m| m.is_a?(Bro::ObjCMethod) && m.is_available? }.each do |m|
                # resolve method conf
                method_owner = members_owner
                full_name = (m.is_a?(Bro::ObjCClassMethod) ? '+' : '-') + m.name
                inherited_initializers = members_conf['inherited_initializers']
                if inherited_initializers
                    # methods are initializers that were inherited from super classes

                    # from owner till members_owner (class it was inherited from) and check configs for exact match
                    method_conf, method_owner = resolve_member_config(model, owner, m, member_owner: members_owner, bottom_limit: members_owner, exact_match: true)

                    # if not found -- then its configuration was not overridden in subclasses (above class this initializer was exposed from)
                    # resolve it as for member owner itself
                    if !method_conf
                        method_conf, method_owner = resolve_member_config(model, members_owner, m, member_owner: members_owner, include_protocols: true)
                    end
                elsif members_owner.is_a?(Bro::ObjCProtocol) && owner.is_a?(Bro::ObjCClass)
                    # methods were added from protocol this class implements

                    # check only in owner, don't go to super -- this to allow method config to be overridden in class that implements protocol
                    method_conf, method_owner = resolve_member_config(model, owner, m, member_owner: members_owner, bottom_limit: owner, exact_match: true)

                    # if no override -- resolve in protocol itself
                    if !method_conf
                        method_conf, method_owner = resolve_member_config(model, members_owner, m, member_owner: members_owner)
                    end
                elsif owner.is_a?(Bro::ObjCCategory)
                    conf = members_conf["methods"] || {}
                    method_conf = model.get_conf_for_key(full_name, conf)
                elsif owner.is_a?(Bro::ObjCProtocol)
                  conf = members_conf["methods"] || {}
                  method_conf = model.get_conf_for_key(full_name, conf)
                else
                    # owner methods -- resolve using inherited
                    method_conf, method_owner = resolve_member_config(model, owner, m, member_owner: members_owner, include_protocols: true)
                end

                # apply default methods configuration (global for all classes)
                method_conf ||= model.get_conf_for_key(full_name, model.default_config("methods") || {})

                a = method_to_java(model, owner_name, owner, method_owner, m, method_conf || {}, seen, false, members_conf['class'], inherited_initializers)
                methods_lines.concat(a[0])
                constructors_lines.concat(a[1])

                # add potential information about method if it has more than
                # one argument and it is name is not overridden in yaml.
                # which will lead to $ signs in name so this will cost another
                # run of bro-gen with updated yaml file.
                # * do not add if method comes from protocol into object
                add_potential_new_entry(owner, a[2]) if a.length > 2 && a[2] != nil && a[2].length > 0 && !(members_owner.is_a?(Bro::ObjCProtocol) && owner.is_a?(Bro::ObjCClass))

                # find out if there is visible default constructor
                has_def_constructor |= full_name == '-init' && (method_conf == nil || !method_conf['exclude'])
            end
            # TODO: temporaly don't add static properties to interfaces
            members.find_all { |m| m.is_a?(Bro::ObjCProperty) && m.is_available? && !(m.is_static? && owner.is_a?(Bro::ObjCProtocol))}.each do |p|
                properties_lines.concat(property_to_java(model, owner, p, members_conf['properties'] || {}, seen))
            end
        end

        data = template_datas[owner_name] || {}
        data['name'] = data['name'] || owner_name
        if owner.is_a?(Bro::ObjCClass)
            unless owner_conf['skip_skip_init_constructor']
                constructors_lines.unshift("protected #{owner_name}(SkipInit skipInit) { super(skipInit); }")
            end
            unless owner_conf['skip_skip_init_constructor']
                constructors_lines.unshift("protected #{owner_name}(Handle h, long handle) { super(h, handle); }")
            end
            if owner_conf['skip_handle_constructor'] == false
                constructors_lines.unshift("@Deprecated protected #{owner_name}(long handle) { super(handle); }")
            end
            unless owner_conf['skip_def_constructor']
                cv = has_def_constructor ? 'public' : 'protected'
                constructors_lines.unshift("#{cv} #{owner_name}() {}")
            end
        elsif owner.is_a?(Bro::ObjCCategory)
            constructors_lines.unshift("private #{owner_name}() {}")
            data['annotations'] = (data['annotations'] || []).push("@Library(#{$library})")
            data['bind'] = "static { ObjCRuntime.bind(#{owner_name}.class); }"
            data['visibility'] = owner_conf['visibility'] || 'public final'
            data['extends'] = 'NSExtensions'
        end
        methods_s = methods_lines.flatten.join("\n    ")
        constructors_s = constructors_lines.flatten.join("\n    ")
        properties_s = properties_lines.flatten.join("\n    ")
        data['methods'] = (data['methods'] || '') + "\n    #{methods_s}\n    "
        data['constructors'] = (data['constructors'] || '') + "\n    #{constructors_s}\n    "
        data['properties'] = (data['properties'] || '') + "\n    #{properties_s}\n    "
        template_datas[owner_name] = data
    end

    template_datas.each do |owner, data|
        c = model.get_class_conf(owner) || model.get_protocol_conf(owner) || model.get_category_conf(owner) || model.get_enum_conf(owner) || {}
        data['imports'] = "\n" + (data['imports'] || [].concat(imports)).uniq().map { |im| "import #{im};" }.join("\n") + "\n"
        data['visibility'] = data['visibility'] || c['visibility'] || 'public'
        data['extends'] = data['extends'] || c['extends'] || 'CocoaUtility'

        data['annotations'] = (data['annotations'] || []).concat(c['annotations'] || []).concat(conf['annotations'] || [])
        data['annotations'] = data['annotations'] && !data['annotations'].empty? ? data['annotations'].uniq.join(' ') : nil
        data['implements'] = data['implements'] || nil
        data['properties'] = data['properties'] || nil
        data['constructors'] = data['constructors'] || nil
        data['members'] = data['members'] || nil
        data['methods'] = data['methods'] || nil
        data['constants'] = data['constants'] || nil
        if c['add_ptr']
            data['ptr'] = "public static class #{owner}Ptr extends Ptr<#{owner}, #{owner}Ptr> {}"
        end
        merge_template(target_dir, package, owner, data['template'] || def_class_template, data)
    end

    #
    # dump suggestions for potentially new classes/enum/protocols
    if !$potential_new_entries.empty?
        puts "\n\n\n"
        puts "\# YAML file potentially missing entries suggestions\n"
        puts "\n\n\n"

        # dumping enums
        potential_enums = $potential_new_entries.select{ |key, value| key.is_a?(Bro::Enum ) || key.is_a?(Bro::EnumValue)  }
        if !potential_enums.empty?
            puts "#enums:"
            puts "\# potentially missing enums"
            puts "#enums:"
            potential_enums.each do |enum, data|

                enum_params = []
                enum_comments = []
                enum_members = enum.values.collect {|e| e.name}
                enum_comments.push( "since #{enum.since}" ) if enum.since

                # get common prefix
                if !enum_members.empty?
                    enum_members.push(enum.name) if enum_members.length == 1 && !enum.name.empty?
                    if enum_members.length == 1
                        prefix = enum_members[0]
                        enum_comments.push("!Prefix invalid!")
                    else
                        min, max = enum_members.minmax
                        idx = min.size.times{|i| break i if min[i] != max[i]}
                        prefix = min[0...idx]
                    end
                    prefix = "" if !enum.name.empty? && prefix.start_with?(enum.name)
                    enum_params.push("prefix: #{prefix}") if !prefix.empty?
                end

                enum_params.push("first: #{enum_members[0]}") if enum.name.empty?
                enum_params = "{" + enum_params.join(", ") + "}"
                enum_comments = enum_comments.empty? ? "" : " \#" + enum_comments.join(", ")
                puts "    #{enum.name.empty? ? 'UNNAMED' : enum.name}: #{enum_params}#{enum_comments}"
            end
            puts "\n\n\n"
        end

        # dumping structs
        potential_structs = $potential_new_entries.select{ |key, value| key.is_a?(Bro::Struct) }
        if !potential_structs.empty?
            puts "\# potentialy missing structs"
            potential_structs.each do |struct, data|
                puts "    #{struct.name}: {}" + (struct.since  ? " \#since #{struct.since}" : "")
            end
            puts "\n\n\n"
        end

        # duming typedefs as structs        struct = td.struct
        potential_typedefs = $potential_new_entries.select{ |key, value| key.is_a?(Bro::Typedef) }
        if !potential_typedefs.empty?
            puts "\# potentialy missing typedefs"
            potential_typedefs.each do |td, data|
                struct = td.struct
                if struct && struct.is_opaque?
                    struct = model.structs.find { |e| e.name == td.struct.name } || td.struct
                end
                next if !struct || struct.is_opaque?
                puts "    #{td.name}: {}" + (td.since  ? " \#since #{td.since}" : "")
            end
            puts "\n\n\n"
        end


        # helper finds if method present in super
        def is_method_in_super(model, cls, full_name)
            while cls.superclass do
                cls = model.objc_classes.find { |e| e.name == cls.superclass }
                conf = model.get_class_conf(cls.name) || {}
                if conf['exclude'] != true
                    (cls.instance_methods + cls.class_methods).find_all { |m| m.is_a?(Bro::ObjCMethod) && m.is_available? }.each do |m|
                        return cls if full_name == m.full_name
                    end

                    # check in super class categories
                    cat = model.objc_categories.find_all{ |c| c.owner == cls.name}.each do |c|
                        (c.instance_methods + c.class_methods).find_all { |m| m.is_a?(Bro::ObjCMethod) && m.is_available? }.each do |m|
                            return cls if full_name == m.full_name
                        end
                    end
                end
            end
            return nil
        end

        def is_method_in_protocol(model, cls, full_name)
            # get all protocols
            protocols = all_protocols(model, cls, {})
            found = protocols.find { |prot, protc| (protc["methods"] || {})[full_name] != nil }
            found[0] if found
            nil
        end

        # dumping classes and protocols
        potential_classes_protos = [
            ["classes", $potential_new_entries.select{|key, value| key.is_a?(Bro::ObjCClass)}],
            ["categories", $potential_new_entries.select{|key, value| key.is_a?(Bro::ObjCCategory)}],
            ["protocols", $potential_new_entries.select{|key, value| key.is_a?(Bro::ObjCProtocol)}]
        ]
        potential_classes_protos.each do |title, entries|
            next if entries.empty?

            # convert to array and sort to have values to be updated first
            puts "\# #{title} to be updated:"
            puts "#{title}:"
            entries.each do |cls, data|
                # find all method information
                bad_methods = data
                is_new_entry = bad_methods == nil
                bad_methods ||= []
                if is_new_entry
                    # it is a new class/proto and information about it has to be extracted
                    (cls.instance_methods + cls.class_methods).find_all { |m| m.is_a?(Bro::ObjCMethod) && m.is_available? }.each do |m|
                        next unless m.name.count(':') > 1 || m.name.include?("With")
                        full_name = (m.is_a?(Bro::ObjCClassMethod) ? '+' : '-') + m.name
                        bad_methods.push([full_name, m.name.tr(':', '$')])
                    end
                end

                # divide bad_methods into two set -- one with methods that has
                # configuration in parent classes (will be added at bottom)
                # as these probably not required to be configured. As once
                # parrent class is configured it configuration will be inherited
                if bad_methods && cls.is_a?(Bro::ObjCClass) && cls.superclass
                    bad_methods_new = []
                    bad_methods_inherited = []
                    bad_methods.each do |full_name, name|
                        super_owner = is_method_in_super(model, cls, full_name) || is_method_in_protocol(model, cls, full_name)
                        if super_owner
                            bad_methods_inherited.push([full_name, name, super_owner.name])
                        else
                            bad_methods_new.push([full_name, name])
                        end
                    end
                else
                    bad_methods_new = bad_methods
                    bad_methods_inherited = []
                end

                if bad_methods.empty?
                    puts "    #{cls.java_name}: {}" + (cls.since  ? " \#since #{cls.since}" : "")
                    next
                end

                puts "    #{cls.java_name}:" + (cls.since  ? " \#since #{cls.since}" : "")
                puts "        methods:"
                bad_methods_list = [[nil, bad_methods_new]]
                bad_methods_list.push([" -- methods available in super, don't config if super is configured --", bad_methods_inherited]) unless bad_methods_inherited.empty?
                bad_methods_list.each do |title, bad_methods|
                    puts "                \##{title}" if title
                    bad_methods.each do |full_name, name|
                        puts "            '#{full_name}':"
                        puts "                \#trim_after_first_colon: true" if (full_name.count(':') > 1)
                        puts "                name: #{name}"
                    end
                end
            end
            puts "\n\n\n"
        end
    end
    # end of dumping suggestions
end
