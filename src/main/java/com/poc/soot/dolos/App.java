package com.poc.soot.dolos;

import soot.util.Chain;
import soot.*;
import soot.SootMethod;
import soot.options.Options;
import java.util.*;
import org.apache.commons.cli.*;

public class App {
    static {
        System.out.println("Dolos - Removing SSL pinning");
    }
    private final static String USER_HOME = System.getProperty("user.home");
    private static String androidJar = USER_HOME + "/Library/Android/sdk/platforms";
    private static Boolean set_print ;


    public static void setupSoot(String androidJar, String apkPath, String outputPath) {
        G.reset();
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_whole_program(true);
        Options.v().set_android_jars(androidJar); 
        Options.v().set_src_prec(Options.src_prec_apk); 
        Options.v().set_process_dir(Collections.singletonList(apkPath)); 
        Options.v().set_process_multiple_dex(true); 
        Options.v().set_include_all(true);
        Options.v().set_output_format(Options.output_format_dex);
        Options.v().set_output_dir(outputPath);
        Options.v().set_force_overwrite(true);
        Options.v().set_validate(true); // Validate Jimple bodies in each transofrmation pack
        // Resolve required classes
        // Scene.v().addBasicClass("java.io.PrintStream",SootClass.SIGNATURES);
        // Scene.v().addBasicClass("java.lang.System",SootClass.SIGNATURES);
        Scene.v().loadNecessaryClasses();
    }

    public static void countMethods(Chain<SootClass> classes) {
        int count = 0;
        for (SootClass classy : classes) {
            for (SootMethod Method : classy.getMethods()) {
                if (Filter.firstFilter(Method)) {
                    count += 1;
                }
            }
        }
        System.out.printf("Count of methods in APK that can be from Certificate Pinner: %d\n", count);
    }


    
    public static void main(String[] args) {

        org.apache.commons.cli.Options options = new org.apache.commons.cli.Options();

        Option inputAPK = new Option("a", "apk", true, "input APK path");
        inputAPK.setRequired(true);
        options.addOption(inputAPK);

        Option output = new Option("o", "output", true, "output path for APK");
        output.setRequired(true);
        options.addOption(output);

        Option method = new Option("m", "method", true, "method to insert print");
        method.setRequired(false);
        options.addOption(method);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd = null; // not a good practice, it serves its purpose

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("Dolos", options);

            System.exit(1);
        }

        if (cmd.hasOption("method")){
            set_print = true;

        } else {
            set_print = false;
        }
        // Soot required setup
        String name_method = cmd.getOptionValue("method") ;

        String apkPath = cmd.getOptionValue("apk");
        String outputPath = cmd.getOptionValue("output");

        setupSoot(androidJar, apkPath, outputPath);

        // print for awareness
        System.out.println(apkPath);

        // Count of classess
        Chain<SootClass> classes = Scene.v().getClasses();
        countMethods(classes);

        // Add a transformation pack in order to add the statement
        PackManager.v().getPack("jtp").add(new Transform("jtp.myLogger", new BodyTransformer() {

            @Override
            protected void internalTransform(Body b, String phaseName, Map<String, String> options) {

                if (Filter.isAndroidMethod(b.getMethod())) {
                        return;
                    }
                  

                          
                UnitPatchingChain units = b.getUnits();
                if (set_print == true){
                    String fqdn_method = b.getMethod().getDeclaringClass()+"."+b.getMethod().getName();
                    if (fqdn_method.equalsIgnoreCase(name_method)){
                        System.out.println(fqdn_method);
                        System.out.println(b.getMethod().getDeclaration());
                        Patch.insertPrintStatement(units, b);
                        } else{

                            return;
                        }
                } else{
                    if (!Filter.firstFilter(b.getMethod())){
                        return;
                
                }   
                    if (Filter.isOkHTTPMethod(units, b)){
                        Patch.insertPrintStatement(units, b);
                        Patch.insertBypass(units, b);
                    } 
                
                
                    return;
                }

                
            }
        }));
        try {
                // Run Soot packs (note that our transformer pack is added to the phase "jtp")
                PackManager.v().runPacks();

        } catch(Exception e){
            System.out.printf("Something went wrong with the validation. Error:\n\n %s", e);

        }

        // Write the result of packs in outputPath
        PackManager.v().writeOutput();



    }

}
