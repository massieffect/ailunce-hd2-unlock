import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.util.*;
public class FindFifo2 extends GhidraScript {
  Address A(long v){ return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v); }
  public void run() throws Exception {
    FunctionManager fm=currentProgram.getFunctionManager();
    DecompInterface dec=new DecompInterface(); dec.openProgram(currentProgram);
    ConsoleTaskMonitor mon=new ConsoleTaskMonitor();
    long[] pools={0x2f18L,0x8364L,0x8544L,0xd6324L};
    Set<Function> fns=new LinkedHashSet<>();
    for(long p: pools){
      Function f=fm.getFunctionContaining(A(p));
      long probe=p;
      while(f==null && probe>p-0x800){ probe-=2; f=fm.getFunctionContaining(A(probe)); }
      println("FF2> pool 0x"+Long.toHexString(p)+" -> function "+(f!=null?f.getName()+"@"+f.getEntryPoint():"NONE"));
      if(f!=null) fns.add(f);
    }
    println("\nFF2> ===== callers of each =====");
    for(Function f: fns){
      StringBuilder sb=new StringBuilder();
      for(Function c: f.getCallingFunctions(mon)) sb.append(c.getName()+"@"+c.getEntryPoint()+" ");
      println(f.getName()+"@"+f.getEntryPoint()+" <- "+sb);
    }
    println("\nFF2> ===== decompiled =====");
    for(Function f: fns){
      DecompileResults r=dec.decompileFunction(f,60,mon);
      if(r!=null&&r.getDecompiledFunction()!=null){
        println("//// "+f.getName()+"@"+f.getEntryPoint()+" ////");
        String c=r.getDecompiledFunction().getC();
        println(c.length()>2600?c.substring(0,2600):c);
      }
    }
  }
}
