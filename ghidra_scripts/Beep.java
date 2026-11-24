import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.util.*;
public class Beep extends GhidraScript {
  Address A(long v){ return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v); }
  public void run() throws Exception {
    FunctionManager fm=currentProgram.getFunctionManager();
    println("B> functions: "+fm.getFunctionCount()+"  base="+currentProgram.getImageBase());
    DecompInterface dec=new DecompInterface(); dec.openProgram(currentProgram);
    ConsoleTaskMonitor mon=new ConsoleTaskMonitor();
    long base=0x0300D000L;
    long[] pools={0x2f18L,0x8364L,0x8544L,0xd6324L};
    Set<Function> fns=new LinkedHashSet<>();
    for(long off: pools){
      long p=base+off;
      Function f=fm.getFunctionContaining(A(p));
      long probe=p;
      while(f==null && probe>p-0x1000){ probe-=2; f=fm.getFunctionContaining(A(probe)); }
      println("B> FIFO-const@0x"+Long.toHexString(p)+" -> "+(f!=null?f.getName()+"@"+f.getEntryPoint():"NONE"));
      if(f!=null) fns.add(f);
    }
    println("\nB> ===== callers =====");
    for(Function f: fns){
      StringBuilder sb=new StringBuilder();
      for(Function c: f.getCallingFunctions(mon)) sb.append(c.getName()+"@"+c.getEntryPoint()+" ");
      println(f.getName()+"@"+f.getEntryPoint()+" <- "+sb);
    }
    println("\nB> ===== decompiled =====");
    int n=0;
    for(Function f: fns){ if(n++>=3) break;
      DecompileResults r=dec.decompileFunction(f,90,mon);
      if(r!=null&&r.getDecompiledFunction()!=null){
        println("//// "+f.getName()+"@"+f.getEntryPoint()+" ////");
        String c=r.getDecompiledFunction().getC();
        println(c.length()>3500?c.substring(0,3500):c);
      }
    }
  }
}
