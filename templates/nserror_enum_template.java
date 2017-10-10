__LICENSE__
package org.robovm.foo;

/*<imports>*/
/*</imports>*/

/*<javadoc>*/
/*</javadoc>*/
/*<annotations>*/
/*</annotations>*/
public enum /*<name>*/ TheName /*</name>*/ implements NSErrorCode {
    /*<values>*/
    /*</values>*/

    /*<bind>*/
    /*</bind>*/
    /*<constants>*/
    /*</constants>*/
    /*<members>*/
    /*</members>*/
    /*<methods>*/
    /*</methods>*/

    private final long n;

    private /*<name>*/ TheName /*</name>*/(long n) { this.n = n; }
    public long value() { return n; }
    public static /*<name>*/ TheName /*</name>*/ valueOf(long n) {
        for (/*<name>*/ TheName /*</name>*/ v : values()) {
            if (v.n == n) {
                return v;
            }
        }
        throw new IllegalArgumentException("No constant with value " + n + " found in "
            + /*<name>*/ TheName /*</name>*/.class.getName());
    }

    // bind wrap to include it in compilation as long as nserror enum is used 
    static { Bro.bind(NSErrorWrap.class); }
    @StronglyLinked
    public static class NSErrorWrap extends NSError {
        protected NSErrorWrap(SkipInit skipInit) {super(skipInit);}

        @Override public NSErrorCode getErrorCode() {
             try {
                 return  /*<name>*/ TheName /*</name>*/.valueOf(getCode());
             } catch (IllegalArgumentException e) {
                 return null;
             }
         }

        public static String getClassDomain() {
            /** must be incerted in value section */
            return /*<name>*/ TheName /*</name>*/.getClassDomain();
        }
    }
}
