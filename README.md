# bro-gen

`bro-gen` is a Ruby script which can be used to generate RoboVM bindings for C/Objective-C libraries and frameworks.

## Requirements

 * libclang 3.3+ (will use the one from Xcode if installed)
 * Ruby
 * Ruby FFI

*Note about Ruby FFI*: If you get clang compiler errors when trying to install the FFI gem try the following:
```
sudo ARCHFLAGS=-Wno-error=unused-command-line-argument-hard-error-in-future gem install ffi
```

## Getting the code

```
git clone git://github.com/MobiDevelop/robovm-bro-gen.git
cd robovm-bro-gen
git submodule init
git submodule update
```

## Usage

```
./bro-gen path/to/put/generated/sources config1.yaml [config2.yaml ...]
```

## YAML config file format

The YAML config files are used to tell the script how to process the functions, classes, enums, structs, etc in a particular framework or library. The supported top level keys are:

 * `package`: The Java package name to use for all classes and interfaces.
 * `include`: A list of other YAML config files needed by this config. Will be resolved relative to the current file.
 * `library`: The library name to use in the `@Library` annotation on generated classes.
 * `framework`: The framework being generated. Only entities in header files from this framework will be included in the generated output (and header files matching `path_match`).
 * `path_match`: A regexp matching header files which contains entities that should be included in the generated output.
 * `clang_args`: List of extra arguments to pass to CLang when parsing the header files. If you generate code for an Objective-C framework you should specify `['-x', 'objective-c']`.
 * `headers`: A list of header files that should be processed relative to the sysroot.
 * `typedefs`: A hash of C/Obj-C type to Java type mappings. These are inherited when including other YAML files.
 * `private_typedefs`: A hash of C/Obj-C type to Java type mappings. These don't get inherited when including other YAML files.
 * `annotations`: Global annotations to be added to every generated class.
 * `enums`: A hash of C enums that should be generated. See below.
 * `classes`: A hash of C structs and Obj-C classes that should be generated. See below.
 * `categories`: A hash of Obj-C categories that should be generated. See below.
 * `protocols`: A hash of Obj-C protocols that should be generated. See below.
 * `functions`: A hash of C functions that should be generated. See below.
 * `values`: A hash of C global values that should be generated. See below.
 * `constants`: A hash of C constants that should be generated. See below.

### About regexps

Many of the keys in the YAML hashes are regexp patterns. A regexp must match the input fully to be a match so there's no need to use ^ and $ at the stared and end of the regexp. Capturing groups in the regexp pattern can be used in the values of the hash. These are referenced using Ruby style placeholders. `#{g[0]}` for the first group, `#{g[1]}` for the second and so on.

### enums

The keys in this hash specify enum names. Only enums that have a matching key in this hash will be generated. The values are also hashes, usually empty (`{}`) but the following keys are supported:

 * `first`: The name of the first member in the enum. Some enums don't specify a name in the header file. This will be used to connect an anonymous enum with a name (the key of the `enums` hash).
 * `prefix`: The prefix of the member names which should be stripped off when generating the Java member name. The script will look for the longest common prefix of the names and use that as prefix by default.
 * `suffix`: A suffix which should be stripped off the end of member names if they end with this suffix.
 * `type`: The C type of the enum. This is used to determine the marshaler to use in the Java code. This can usally be determined automatically be the script.
 * `merge_with`: Another enum which this enum should be merged with.
 * `bits`: Boolean specifying whether this should be bound as a Java enum or as a Java class inheriting from Bits. Should be `true` if the C enum is a bitmask kind of enum. For Apple's header files this can usually be determined automatically by the script.
 * `skip_none`: Bits subclasses will by default get a `None` value with no bits set unless a `None` value already exists in the C enum. Set this to `true` to prevent a `None` value to be added.
 * `exclude`: Boolean specifying whether this enum should be excluded and not generated.
 * `ignore`: Regexp matching enum members that should be ignored.
 * `marshaler`: Specifies the `@Marshaler` to use when marhsaling this enum. E.g. `Bits.AsMachineSizedIntMarshaler`, `ValuedEnum.AsMachineSizedUIntMarshaler`. Can ususally be determined automatically by the script.
 * `<MemberName>`: Used to rename a member completely. Use the C member name as key and the Java member name as value.

### classes

The keys in this hash specify class/struct name regexp patterns. Only classes/structs that have a matching key in this hash will be generated. The values are also hashes with the following supported keys:

 * `exclude`: Boolean specifying whether this class should be excluded and not generated.
 * `annotations`: List of class level annotations to be added to the generated class.
 * `visibility`: The visibility (access modifiers) of the generated class. The default is `public`.
 * `name`: The name of the generated Java class. If not specified the C/Objective-C name will be used.
 * `extends`: The name of the Java class the generated class will derive from.
 * `protocols`: A list of Java interface names the generated class will implement.
 * `skip_skip_init_constructor`: Boolean. If `true` no `protected Foo(SkipInit)` constructor will be generated for an Obj-C class.
 * `skip_def_constructor`: Boolean. If `true` no default constructor will be generated for an Obj-C class.
 * `add_ptr`: Boolean. If `true` an inner Ptr class will be created even if the type doesn't resolve to a struct or Obj-C class. Not needed in most cases.
 * `properties`: See below.
 * `methods`: See below.
 * `<MemberName>`: A hash which can be used to specify config for a particular struct member. The value is a hash with the following keys:
   * `name`: The name of the struct member. Allows renaming of struct members.
   * `type`: The Java type of the struct member.

### protocols

The keys in this hash specify Objective-C protocol name regexp patterns. Only protocols that have a matching key in this hash will be generated. A Java interface will be generated for each matching protocol along with an adapter class implementing all methods in the interface.

The values are also hashes with the following supported keys:

 * `exclude`: Boolean specifying whether this class should be excluded and not generated.
 * `visibility`: The visibility (access modifiers) of the generated class. The default is `public`.
 * `name`: The name of the generated Java class. If not specified the C/Objective-C name will be used.
 * `extends`: The name of the Java class the generated class will derive from.
 * `protocols`: A list of Java interface names the generated class will implement.
 * `properties`: See below.
 * `methods`: See below.
 * `skip_adapter`: Boolean specifying whether an adapter should be generated for the Java interface. The default is `true`.

### categories

The keys in this hash specify regexps that matches Objective-C category names or Objective-C category target class names or both of them concatenated and separated by a `@`. For categories targeting classes in the current framework the default is to add the category methods to that class. For other categories the default is to create a new class with the name `<category>Extensions` that extends `NSExtensions` and that has static methods for each category method.

 * `exclude`: Boolean specifying whether this category should be excluded and not generated.
 * `protocol`: Boolean. If `true` the category will be treated as a protocol. A matching config has to exist in the `protocols` hash. Used for informal protocols.
 * `owner`: The name of the class the category methods should be added to. If not specified the methods will be added to a new class called `<category>Extensions`, e.g. `NSValueExtensions`.
 * `properties`: See below.
 * `methods`: See below.

### functions

The keys in this hash specify regexps that matches C function names. Functions not matching any key in this hash will be ignored. Java doesn't have global functions so each function will be convered into a method on a particular class. If no class is explicitly specified it will be assigned to a class named the same as the framework code is being generated for. If not generating code for a framework the default is to add functions to a class named `Functions`.

The generated method for a function will by default be an instance method if the first parameter of the C function is a pointer to the class or struct corresponding to the Java class it will be added to. Otherwise is will be static.

Note that Bro does not currently support variable parameter functions so such methods will be ignored.

 * `exclude`: Boolean specifying whether this function should be excluded and not generated.
 * `class`: The Java class this function should be added to.
 * `visibility`: The visibility (access modifiers) of the generated method. The default is `public`.
 * `name`: The name of the generated method. The default is the name of the C function.
 * `static`: Boolean. If `true` the generated method will always be static.
 * `return_type`: The Java return type of the generated method. The default is determined from the function's return type.
 * `parameters`: A hash with regexp keys matching parameter names. The values of the hash are
   * `name`: The name to use for the parameter in the Java method.
   * `type`: The Java parameter type.

### values

The keys in this hash specify regexps that matches C global value names. Values not matching any key in this hash will be ignored. Java doesn't have global values so each value will be converted into a getter method and a setter method (if not readonly) on a particular class. If no class is explicitly specified they will be assigned to a class named the same as the framework code is being generated for. If not generating code for a framework the default is to add value methods to a class named `Functions`.

 * `exclude`: Boolean specifying whether this value should be excluded and not generated.
 * `class`: The Java class the methods for this value should be added to.
 * `visibility`: The visibility (access modifiers) of the generated methods. The default is `public`.
 * `name`: The name of the generated methods. The default is the name of the C value.
 * `type`: The Java type of the value. The default is determined from the values's type.
 * `readonly`: Boolean specifying whether this is a readonly value. `const` values are always readonly.
 * `dereference`: Boolean specifying whether the address of the looked up symbol should be dereferenced (the default) or used as is. The default is `true`.

### constants

The keys in this hash specify regexps that matches C constants (macros). Constants not matching any key in this hash will be ignored. Java doesn't have global constants so each constant will be added as a `static final` field on a particular class. If no class is explicitly specified it will be assigned to a class named the same as the framework code is being generated for. If not generating code for a framework the default is to add constants to a class named `Functions`.

Enums in the framework or library being generated which don't have a match in the `enums` config will be convered into constants and matched against the keys in this hash.

 * `exclude`: Boolean specifying whether this constant should be excluded and not generated.
 * `class`: The Java class the constant should be added to.
 * `name`: The name of the generated constant. The default is the name of the C constant.
 * `type`: The Java type of the constant. The default is determined from the constant's type.
 * `visibility`: The visibility (access modifiers) of the generated field. The default is `public`.

### properties

The keys in a `properties` hash are regexp patterns matching Objective-C property names. The script will generate getter and setter (if not readonly) methods for the property. The values of the hash are hashes with the following keys:

 * `exclude`: Boolean specifying whether this property should be excluded and not generated.
 * `name`: Overrides the name of the property.
 * `type`: Overrides the Java type of the property.
 * `visibility`: The visibility (access modifiers) of the generated methods. The default is `public`.
 * `readonly`: Boolean specifying whether this is a readonly property. If the property is readonly in Obj-C it will always be readonly.
 * `omit_prefix`: Boolean specifying whether Java Bean style `set`, `get`/`is` should be removed from the name of the property.

### methods

The keys in a `methods` hash are regexp patterns matching Objective-C method (selector) names. The Obj-C selector will be prefixed with `+` for static methods and `-` for instance methods before finding a match.

The script will be default use the selector with all `:` replaced by `$` as Java method name. For setter like methods the ending `:` will be dropped by default.

Note that Bro does not currently support variable parameter methods so such methods will be ignored.

The values of the hash are hashes with the following keys:

 * `exclude`: Boolean specifying whether this method should be excluded and not generated.
 * `visibility`: The visibility (access modifiers) of the generated method. The default is `public`.
 * `name`: Overrides the name of the method.
 * `property`: Boolean specifying whether the method should be convered to a Java property getter. If `true` the and the method takes 0 parameters and returns something the method name will be transformed by upcasing the first character in the Obj-C name and prefixing `get` (or `is` if it returns `boolean`).
 * `trim_after_first_colon`: Boolean. If `true` the Java method name will be the part of the method selector name until the first `:`.
 * `return_type`: The Java return type of the generated method. The default is determined from the Obj-C method's return type.
 * `parameters`: A hash with parameter indexes or regexp keys matching parameter names. The values of the hash are
   * `name`: The name to use for the parameter in the Java method.
   * `type`: The Java parameter type.
