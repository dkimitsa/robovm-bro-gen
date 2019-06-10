#!/usr/bin/env ruby


# 
# Simple tools that uses clang -ast-dump to find packed structs and 
# warn if these struct are not annotated in yaml
# usage: find-pragma-pack <yaml>
# 

require 'yaml'
require 'fileutils'
require 'pathname'
require 'tmpdir'

module Bro
    class Entity
        attr_accessor :name
        def initialize(model, name)
            @name = name
            @model = model
        end
    end

    class Typedef < Entity
        attr_accessor :struct
        def initialize(model, name, struct)
            super(model, name)
            @struct = struct
        end
    end

    class Struct < Entity
        attr_accessor :id, :align
        def initialize(model, id, name, align)
            super(model, name)
            @id = id
            @align = align
        end
    end

    class Model
        attr_accessor :structs, :typedefs

        def initialize(conf)
            @conf = conf
            @conf_classes = @conf['classes'] || {}
            @typedefs = []
            @structs = []
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
    end
end


def target_file(dir, package, name)
    File.join(dir, package.gsub('.', File::SEPARATOR), "#{name}.java")
end

module ClangState
    NONE = 0
    IN_RECORD = 1
    IN_TYPEDEF = 2
end
def clang_preprocess(model, args)
    # specifies what section we are processing right now 

    tmp_dir = Dir.mktmpdir()
    at_exit { FileUtils.remove_entry(tmp_dir)}

    dummy_m = File.join(tmp_dir, '__dummy.m')
    File.open(dummy_m, 'w') do |f|
    end

    state = ClangState::NONE
    entry_name = nil
    entry_id = nil
    entry_value = nil
    lines = IO.popen(['clang'] + args + [ '-c', dummy_m]).readlines
    lines.each do |line|
        if state != ClangState::NONE && line.start_with?('|-')
            # new command starts -- reset 
            state = ClangState::NONE
            entry_name = nil
            entry_id = nil
            entry_value = nil
        end
        
        if state == ClangState::IN_RECORD
            #
            # inside struct definition
            #

            # looking for 'MaxFieldAlignmentAttr'
            if line.start_with?('| |-MaxFieldAlignmentAttr') && line.include?('Implicit')
                # cut value Implicit 32
                if line =~ /^.*Implicit (\d+).*/i
                    entry_value = $1.to_i

                    # packed struct, add to the list 
                    s = Bro::Struct.new(model, entry_id, entry_name, entry_value)
                    model.structs.push s
                end
            end
        elsif state == ClangState::IN_TYPEDEF
            #
            # inside typedef definition
            #

            # looking for |     `-Record
            if line =~ /^.*Record 0x(\h+) .*/i
                record_id = $1

                # check if such struct is added as packed 
                s = model.structs.find { |e| e.id == record_id }
                if s 
                    t = Bro::Typedef.new model, entry_name, s
                    model.typedefs.push t
                end
            end
        else 
            # 
            #  finding type of record to start 
            # 
            if line.start_with?('|-RecordDecl')
                # get id 
                if line =~ /^.*RecordDecl 0x(\h+) <.*/i
                    entry_id = $1
                end
                # get name 
                if line =~ /^.* struct\s+(\w*)\s*definition.*/i
                    entry_name = $1
                    entry_name = entry_name.split(' ').last
                end
                state = ClangState::IN_RECORD                
            elsif line.start_with?('|-TypedefDecl')
                # get id 
                if line =~ /^.*TypedefDecl 0x(\h+) <.*/i
                    entry_id = $1
                end
                # get name 
                # replace 'invalid sloc' to dummy string just to be able apply same regex
                name_line=line.gsub('<invalid sloc>', 'col:0')
                # also replace line location to col, to use same regex
                name_line=name_line.gsub(/line:\d+:\d+ /i, 'col:0 ')
                if name_line =~ /^.*col:\d+ ([^\']*)\'.*/i
                    entry_name = $1.strip
                    entry_name = entry_name.split(' ').last
                end
                state = ClangState::IN_TYPEDEF
            end
        end
    end
end


$mac_version = nil
$ios_version = '12.2'
$target_platform = 'ios'
xcode_dir = `xcode-select -p`.chomp
sysroot = "#{xcode_dir}/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS#{$ios_version}.sdk"
unless File.exist?(sysroot)
   sysroot = "#{xcode_dir}/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk"
end

script_dir = File.expand_path(File.dirname(__FILE__))
global = YAML.load_file("#{script_dir}/global.yaml")

ARGV[0..-1].each do |yaml_file|
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

    clang_preprocess_args = ['-Xclang', '-ast-dump', '-Wunguarded-availability-new', '-Wno-partial-availability', '-fno-diagnostics-color', '-fdiagnostics-color=never', 
        '-DOS_OBJECT_HAVE_OBJC_SUPPORT=1', '-DTARGET_OS_MAC=1', '-DTARGET_OS_IOS=1', '-D__IPHONE_OS_VERSION_MIN_REQUIRED=__IPHONE_12_2',
        '-arch', 'arm64', '-fblocks', '-isysroot', sysroot]

    headers.each do |e|
        clang_preprocess_args.push('-include')
        clang_preprocess_args.push(File.join(header_root, e))
    end

    framework_roots.each do |e|
        clang_preprocess_args << "-F#{e}" if e != sysroot
    end

    clang_preprocess_args += conf['clang_args'] if conf['clang_args']

    # preprocess files using clang to expand all macro to be able better understand
    # attributes and enum/types definitions
    model = Bro::Model.new conf
    clang_preprocess(model, clang_preprocess_args)

    # merge structs and typedefs into single map (typedefs will overried structs with same name )
    items = {}
    model.structs.find_all { |e| e.name && !e.name.empty? }.each do |struct|
        c = model.get_class_conf(struct.name)
        next unless c && !c['exclude']
        items[struct.name] = struct, c
    end
    model.typedefs.each do |td|
        c = model.get_class_conf(td.name)
        next unless c && !c['exclude']
        items[td.name] = td.struct, c
    end

    notes = []
    items.each do |name, a|
        struct, c = a
        # check if this struct is properly configured 
        expected = "@Packed(#{struct.align / 8})"
        annotations = c['annotations'] || []
        if !annotations.include?(expected)
            # found struct without annotation 
            notes.push "    #{name}:"
            notes.push "        annotations: ['#{expected}']"
        end
    end

    if !notes.empty?
        puts "classes:"
        notes.each { |line| puts line}
    end
end
