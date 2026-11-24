import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.util.*;
public class Dis extends GhidraScript {
  Address A(long v){ return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v); }
  void dumpFunc(Function f, int max){
    if(f==null){ println("  (null)"); return; }
    Listing l=currentProgram.getListing();
    InstructionIterator it=l.getInstructions(f.getBody(),true);
    int n=0;
    while(it.hasNext() && n<max){ Instruction ins=it.next();
      String ref="";
      for(ghidra.program.model.symbol.Reference r: ins.getReferencesFrom()) ref+=" ->"+r.getToAddress();
      println(String.format("   %s  %-22s%s", ins.getAddress(), ins.toString(), ref)); n++; }
  }
  public void run() throws Exception {
    FunctionManager fm=currentProgram.getFunctionManager();
    ConsoleTaskMonitor mon=new ConsoleTaskMonitor();
    Function bw=fm.getFunctionAt(A(0x0300febcL));
    println("D> ===== BEEP WRITER FUN_0300febc (confirm FIFO write) =====");
    dumpFunc(bw,70);
    println("\nD> ===== its 9 callers, and THEIR callers (to reach boot) =====");
    for(Function c: bw.getCallingFunctions(mon)){
      StringBuilder up=new StringBuilder();
      for(Function cc: c.getCallingFunctions(mon)) up.append(cc.getName()+" ");
      println("  "+c.getName()+"@"+c.getEntryPoint()+"  <- "+up);
    }
    println("\nD> ===== FUN_03015224 (near FIFO const) =====");
    dumpFunc(fm.getFunctionAt(A(0x03015224L)),40);
  }
}
