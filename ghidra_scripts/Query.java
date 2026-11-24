import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.ConsoleTaskMonitor;
public class Query extends GhidraScript {
  Address A(long v){ return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v); }
  public void run() throws Exception {
    FunctionManager fm=currentProgram.getFunctionManager();
    println("Q> functions: "+fm.getFunctionCount());
    long[] strs={0x0309F434L,0x030A26ECL,0x03099668L,0x030AE030L}; // Hal_BeepPlay, beepType, beepPhase, KeyBeepOn (string text addrs)
    String[] nm={"Hal_BeepPlay","beepType","beepPhase","KeyBeepOn"};
    DecompInterface dec=new DecompInterface(); dec.openProgram(currentProgram);
    ConsoleTaskMonitor mon=new ConsoleTaskMonitor();
    for(int k=0;k<strs.length;k++){
      Address sa=A(strs[k]);
      println("\nQ> string '"+nm[k]+"' @"+sa);
      ReferenceIterator ri=currentProgram.getReferenceManager().getReferencesTo(sa);
      int c=0;
      for(Reference r: ri){ c++;
        Function f=fm.getFunctionContaining(r.getFromAddress());
        println("   REF from "+r.getFromAddress()+" ("+r.getReferenceType()+") func="+(f!=null?f.getName()+"@"+f.getEntryPoint():"-"));
      }
      if(c==0) println("   (no refs)");
    }
    // also: is there a pointer to Hal_BeepPlay string at 0x0302a7d8, and is THAT in a function?
    Address ptr=A(0x0302a7d8L);
    Function pf=fm.getFunctionContaining(ptr);
    println("\nQ> loc 0x0302a7d8 (pointer-to-string): func="+(pf!=null?pf.getName()+"@"+pf.getEntryPoint():"none")+" instr?="+(getInstructionAt(ptr)!=null));
    ReferenceIterator ri2=currentProgram.getReferenceManager().getReferencesTo(ptr);
    for(Reference r: ri2){ println("   who references the pointer loc: "+r.getFromAddress()+" "+r.getReferenceType()); }
  }
}
