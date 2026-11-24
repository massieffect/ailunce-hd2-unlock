import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.util.*;
public class FindFifo extends GhidraScript {
  Address A(long v){ return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v); }
  public void run() throws Exception {
    FunctionManager fm=currentProgram.getFunctionManager();
    DecompInterface dec=new DecompInterface(); dec.openProgram(currentProgram);
    ConsoleTaskMonitor mon=new ConsoleTaskMonitor();
    long[] pools={0x2f18L,0x8364L,0x8544L,0xd6324L};   // base 0 -> va == file off
    Set<Function> beepFns=new LinkedHashSet<>();
    for(long p: pools){
      Address pa=A(p);
      println("FF> pool @"+pa+" references:");
      for(Reference r: getReferencesTo(pa)){
        Function f=fm.getFunctionContaining(r.getFromAddress());
        println("    from "+r.getFromAddress()+" func="+(f!=null?f.getName()+"@"+f.getEntryPoint():"-"));
        if(f!=null) beepFns.add(f);
      }
    }
    println("\nFF> ===== BEEP-WRITER FUNCTIONS & CALLERS =====");
    for(Function f: beepFns){
      StringBuilder sb=new StringBuilder();
      for(Function c: f.getCallingFunctions(mon)) sb.append(c.getName()+"@"+c.getEntryPoint()+" ");
      println("FUNC "+f.getName()+"@"+f.getEntryPoint()+"  <- callers: "+sb);
    }
    println("\nFF> ===== DECOMPILED =====");
    int n=0;
    for(Function f: beepFns){ if(n++>=3) break;
      DecompileResults r=dec.decompileFunction(f,60,mon);
      if(r!=null&&r.getDecompiledFunction()!=null){
        println("//// "+f.getName()+"@"+f.getEntryPoint()+" ////");
        String c=r.getDecompiledFunction().getC();
        println(c.length()>3000?c.substring(0,3000):c);
      }
    }
  }
}
