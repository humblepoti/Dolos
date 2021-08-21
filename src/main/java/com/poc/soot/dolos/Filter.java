package com.poc.soot.dolos;

import soot.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class Filter {

    public static boolean isAndroidMethod(SootMethod sootmethod) {
        String methSig = sootmethod.getName();
        List<String> androidPrefixPkgNames = Arrays.asList("android.", "com.google.android", "androidx.",
                "com.fasterxml.jackson");
        return androidPrefixPkgNames.stream().map(methSig::startsWith).reduce(false, (res, curr) -> res || curr);
    }

    public static boolean isOkHTTPMethod(UnitPatchingChain units, Body body){
        List<Pattern> patterns = Arrays.asList(Pattern.compile("^\\s*(\\$[A-Za-z0-9_]*)\\s*=\\s*(\\(java.security.cert.X509Certificate\\))\\s*(\\$[A-Za-z0-9_]*)"), 
        Pattern.compile("^\\s*(\\$[A-Za-z0-9_]*)\\s*=\\s*(virtualinvoke)*\\s*(\\$[A-Za-z0-9_]*)\\.(\\<java\\.lang\\.String:)\\s*(boolean)\\s*(equals\\(java\\.lang\\.Object\\)\\>)([\\(\\\\\\\"]*sha256[\\/\\\\\\\"\\)]*)"),
        Pattern.compile("^\\s*(\\$[A-Za-z0-9_]*)\\s*=\\s*(virtualinvoke)*\\s*(\\$[A-Za-z0-9_]*)\\.(\\<java\\.lang\\.String:)\\s*(boolean)\\s*(equals\\(java\\.lang\\.Object\\)\\>)([\\(\\\\\\\"]*sha1[\\/\\\\\\\"\\)]*)"),
        Pattern.compile("^\\s*(\\$[A-Za-z0-9_]*)\\s*=\\s*(staticinvoke)\\s<([A-Za-z_.:]*\\s*[A-Za-z0-9_.:]*)\\s*([A-Za-z_.:]*\\s*)([A-Za-z0-9_]*\\(java.security.cert.X509Certificate\\))>(\\(\\$[A-Za-z0-9_]*\\))"),
        Pattern.compile("^\\s*(virtualinvoke)\\s*(\\$[A-Za-z0-9_.]*<java.lang.StringBuilder:)\\s(java.lang.StringBuilder)\\s([A-Za-z0-9]*\\(java.lang.String\\))>(\\(\\\"\\\\n\\s*Pinned\\s*certificates\\s*for\\s*\\\"\\))"),
        Pattern.compile("^\\s*(specialinvoke)\\s([A-Za-z$0-9_.]*)<(javax.net.ssl.SSLPeerUnverifiedException:)\\s*(void)\\s<(init)>(\\(java.lang.String\\))>(\\([$A-Za-z0-9]*\\))"));

        // $r6 = (java.security.cert.X509Certificate) $r5
        // $r8 = staticinvoke <m.l: n.i a(java.security.cert.X509Certificate)>($r6)
        // $r8 = staticinvoke <okhttp3.CertificatePinner: okio.ByteString sha1(java.security.cert.X509Certificate)>($r6)
        // $z0 = virtualinvoke $r10.<java.lang.String: boolean equals(java.lang.Object)>("sha256/")
        // $z0 = virtualinvoke $r10.<java.lang.String: boolean equals(java.lang.Object)>("sha1/")
        // virtualinvoke $r16.<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>("\n  Pinned certificates for ")
        // virtualinvoke $r13.<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>("\n  Pinned certificates for ")
        // specialinvoke $r18.<javax.net.ssl.SSLPeerUnverifiedException: void <init>(java.lang.String)>($r1)
        // specialinvoke $r15.<javax.net.ssl.SSLPeerUnverifiedException: void <init>(java.lang.String)>($r1)

        int count = 0;
        // System.out.printf("Name of method: %s\n", body.getMethod());

        for (Unit item: units){
            // System.out.println(item.toString());
            
            for (Pattern pattern: patterns){
                Matcher regexMatcher = pattern.matcher(item.toString());
                if (regexMatcher.find()){
                    
                    // System.out.printf("Matched: %s\n", regexMatcher.group(0)); Uncomment this line if you want to see the Jimple statements that matched one of the signatures. 
                    // System.out.println(item.toString());
                    count += 1;        
                }
            }
            
        }
        if (count >= (patterns.size()) ){
            System.out.printf("This method %s seems to be responsible to check ssl pinning (CertificatePinner/okHttp3). It was detected that %d or more patterns are present within the instructions of this method.\n", body.getMethod(), count);
            return true;
        }
        return false;
    }

    public static boolean firstFilter(SootMethod sootMethod){
            
            if ((sootMethod.toString().contains("(java.lang.String,java.util.List)>") && sootMethod.toString().contains("void")) || (sootMethod.toString().contains("(java.lang.String,kotlin.jvm.functions.Function0)>") && sootMethod.toString().contains("void")))
            {
                return true;
            }            
            return false;
    }


}