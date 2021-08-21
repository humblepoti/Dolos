package com.poc.soot.dolos;

import java.util.ArrayList;
import java.util.List;

import soot.*;
import soot.javaToJimple.LocalGenerator;
import soot.jimple.AssignStmt;
import soot.jimple.EqExpr;
import soot.jimple.IfStmt;
import soot.jimple.IntConstant;
import soot.jimple.InvokeStmt;
import soot.jimple.Jimple;
import soot.jimple.JimpleBody;
import soot.jimple.StringConstant;

public class Patch {
    private static Local generateNewLocal(Body body, Type type) {
        LocalGenerator lg = new LocalGenerator(body);
        return lg.generateLocal(type);
    }

    public static void insertPrintStatement(UnitPatchingChain units, Body b){
        JimpleBody body = (JimpleBody) b;
        List<Unit> generatedUnits = new ArrayList<>();  

        String content = String.format("%s Beginning of method %s", "<Dolos - Instrumentation>", body.getMethod().getSignature());
        Local psLocal = generateNewLocal(body, RefType.v("java.io.PrintStream"));

        SootField sysOutField = Scene.v().getField("<java.lang.System: java.io.PrintStream out>");
            
        AssignStmt sysOutAssignStmt = Jimple.v().newAssignStmt(psLocal, Jimple.v().newStaticFieldRef(sysOutField.makeRef()));
        generatedUnits.add(sysOutAssignStmt);

        // // Create println method call and provide its parameter
        SootMethod printlnMethod = Scene.v().grabMethod("<java.io.PrintStream: void println(java.lang.String)>");
        Value printlnParamter = StringConstant.v(content);
        final InvokeStmt printlnMethodCallStmt = Jimple.v().newInvokeStmt(Jimple.v().newVirtualInvokeExpr(psLocal, printlnMethod.makeRef(), printlnParamter));
        generatedUnits.add(printlnMethodCallStmt);

        units.insertBefore(generatedUnits, body.getFirstNonIdentityStmt());

        b.validate();
        System.out.printf("Print statement succesfully added to the method %s.\n", body.getMethod().getName());

    }   

    public static void insertBypass(UnitPatchingChain units, Body b){
        
        List<Unit> generatedUnits2 = new ArrayList<>();

        Value zero = IntConstant.v(0);
        Value zero_1 = IntConstant.v(0);
        EqExpr equalExpr = Jimple.v().newEqExpr(zero, zero_1);

        Unit d = units.getFirst();
        
        for (Unit item : units){
            if (item.toString().equals("return")){
                d = item;
                break;
            }
        }


        IfStmt ifStmt = Jimple.v().newIfStmt(equalExpr, d);
        generatedUnits2.add(ifStmt);

        Unit insertPoint = units.getFirst();
        
        for (Unit item: units){
            if(item.toString().contains("<Dolos - Instrumentation>")){
                insertPoint = item;
                break;
            }
        }
       
        units.insertAfter(generatedUnits2, insertPoint);

        
      
        // Validate the body to ensure that our code injection does not introduce any problem (at least statically)
        b.validate();
        System.out.printf("The %s method was successfully patched. A condition that is always true was added to avoid validation of certificates. In addition a print statement was added in the beginning of the method call to log its invoke in logcat.\n", b.getMethod());
    
    }

}