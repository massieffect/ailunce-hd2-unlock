import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.util.*;
public class Trace extends GhidraScript {
  Address A(long v){ return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v); }
  public void run() throws Exception {
    FunctionManager fm=currentProgram.getFunctionManager();
    ConsoleTaskMonitor mon=new ConsoleTaskMonitor();
    long[] gens={0x03015224L,0x030154f0L};
    for(long g: gens){
      Address ga=A(g);
      println("T> ===== refs to tone-gen @0x"+Long.toHexString(g)+" =====");
      for(Reference r: getReferencesTo(ga)){
        Function from=fm.getFunctionContaining(r.getFromAddress());
        println("   "+r.getReferenceType()+" from "+r.getFromAddress()+" in "+(from!=null?from.getName()+"@"+from.getEntryPoint():"DATA/table"));
      }
      Function gf=fm.getFunctionAt(ga);
      if(gf!=null){ print("   direct callers: ");
        for(Function c: gf.getCallingFunctions(mon)) print(c.getName()+"@"+c.getEntryPoint()+" "); println(""); }
    }
    // Also: find who references the sine table 0x30997cc and the FIFO const location 0x300ff18
    println("\nT> ===== refs to sine-table 0x30997cc =====");
    for(Reference r: getReferencesTo(A(0x030997ccL))){
      Function from=fm.getFunctionContaining(r.getFromAddress());
      println("   from "+r.getFromAddress()+" in "+(from!=null?from.getName()+"@"+from.getEntryPoint():"-"));
    }
  }
}
