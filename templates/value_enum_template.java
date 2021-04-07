__LICENSE__
package org.robovm.foo;

/*<imports>*/
/*</imports>*/

/*<javadoc>*/
/*</javadoc>*/
/*<annotations>*/
/*</annotations>*/
@Marshaler(/*<name>*/ClassName/*</name>*/.Marshaler.class)
/*<visibility>*/ public /*</visibility>*/ class /*<name>*/ClassName/*</name>*/ 
    extends /*<extends>*/Object/*</extends>*/
    /*<implements>*//*</implements>*/ {

    static { Bro.bind(/*<name>*/ClassName/*</name>*/.class); }

    /*<marshalers>*/
    /*</marshalers>*/

    /*<constants>*/
    /*</constants>*/
    
    private static /*<name>*/ClassName/*</name>*/[] values = new /*<name>*/ClassName/*</name>*/[] {/*<value_list>*//*</value_list>*/};

    /*<name>*/ClassName/*</name>*/ (String getterName) {
        super(Values.class, getterName);
    }
    /*<name>*/ClassName/*</name>*/ (/*<type>*/Type/*</type>*/ value) {
        super(value);
    }

    public static /*<name>*/ClassName/*</name>*/ valueOf(/*<type>*/Type/*</type>*/ value) {
        synchronized (/*<name>*/ClassName/*</name>*/.class) {
            for (/*<name>*/ClassName/*</name>*/ v : values) {
                if (v.isAvailable() && v.value().equals(value)) {
                    return v;
                }
            }
            // entry was not known compilation time. probably new entry available on new OS version, extending instead
            // of crashing with exception
            /*<name>*/ClassName/*</name>*/ v = new /*<name>*/ClassName/*</name>*/(value);
            values = Arrays.copyOf(values, values.length + 1);
            values[values.length - 1] = v;
            return v;
        }
    }
    
    /*<methods>*/
    /*</methods>*/
    
    /*<annotations>*/
    /*</annotations>*/
    public static class Values {
    	static { Bro.bind(Values.class); }

        /*<values>*/
        /*</values>*/
    }
}
